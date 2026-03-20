package cz.muni.xmichalk.traverser;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import cz.muni.xmichalk.dto.BundleQueryResultDTO;
import cz.muni.xmichalk.dto.ConnectorDTO;
import cz.muni.xmichalk.integrity.IIntegrityVerifier;
import cz.muni.xmichalk.models.*;
import cz.muni.xmichalk.provServiceAPI.IProvServiceAPI;
import cz.muni.xmichalk.provServiceTable.IProvServiceTable;
import cz.muni.xmichalk.traversalPriority.ETraversalPriority;
import cz.muni.xmichalk.traversalPriority.UnsupportedTraversalPriorityException;
import cz.muni.xmichalk.validity.EValidityCheck;
import cz.muni.xmichalk.validity.IValidityVerifier;
import cz.muni.xmichalk.validity.UnsupportedValidityCheckException;
import org.openprovenance.prov.model.QualifiedName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class Traverser {
    private final IProvServiceTable provServiceTable;
    private final IProvServiceAPI provServiceAPI;
    private final IIntegrityVerifier integrityVerifier;
    private final Map<EValidityCheck, IValidityVerifier> validityVerifiers;
    private final Map<ETraversalPriority, Comparator<ItemToTraverse>> traversalPriorityComparators;
    private static final Logger log = LoggerFactory.getLogger(Traverser.class);
    private final int concurrencyDegree;
    private final boolean preferProvServiceFromConnectors;
    private final boolean omitEmptyResults;

    public Traverser(
            IProvServiceTable traverserTable,
            IProvServiceAPI provServiceAPI,
            IIntegrityVerifier integrityVerifier,
            int concurrencyDegree,
            boolean preferProvServiceFromConnectors,
            boolean omitEmptyResults,
            Map<EValidityCheck, IValidityVerifier> validityCheckers,
            Map<ETraversalPriority, Comparator<ItemToTraverse>> traversalPriorityComparators
    ) {
        this.provServiceTable = traverserTable;
        this.provServiceAPI = provServiceAPI;
        this.integrityVerifier = integrityVerifier;
        this.concurrencyDegree = concurrencyDegree;
        this.preferProvServiceFromConnectors = preferProvServiceFromConnectors;
        this.omitEmptyResults = omitEmptyResults;
        this.validityVerifiers = validityCheckers;
        this.traversalPriorityComparators = traversalPriorityComparators;
        log.info(
                "Instantiated traverser with concurrency degree: {}, preferProvServiceFromConnectors: {}",
                concurrencyDegree,
                preferProvServiceFromConnectors
        );
    }

    public Map<EValidityCheck, IValidityVerifier> getValidityVerifiers() {
        return validityVerifiers;
    }

    public Map<ETraversalPriority, Comparator<ItemToTraverse>> getTraversalPriorityComparators() {
        return traversalPriorityComparators;
    }

    public TraversalResults traverseChain(
            QualifiedName startBundleId,
            QualifiedName startNodeId,
            TraversalParams traversalParams
    ) {
        Comparator<ItemToTraverse> traversalPriorityComparator =
                traversalPriorityComparators.get(traversalParams.traversalPriority);
        if (traversalPriorityComparator == null) {
            String errorMessage =
                    "No traversal priority comparator registered for: " + traversalParams.traversalPriority;
            log.error(errorMessage);
            throw new UnsupportedTraversalPriorityException(errorMessage);
        }

        TraversalState traversalState = new TraversalState(
                ConcurrentHashMap.newKeySet(),
                ConcurrentHashMap.newKeySet(),
                new ConcurrentHashMap<>(),
                new ConcurrentHashMap<>(),
                new PriorityBlockingQueue<>(10, traversalPriorityComparator),
                new ConcurrentLinkedQueue<>(),
                new ConcurrentLinkedQueue<>()
        );

        traversalState.toTraverseQueue.add(new ItemToTraverse(
                startBundleId,
                startNodeId,
                null,
                provServiceTable.getServiceUri(startBundleId.getUri()),
                true,
                new ArrayList<>(traversalParams.validityChecks.stream()
                                        .map((EValidityCheck check) -> new AbstractMap.SimpleImmutableEntry<EValidityCheck, Boolean>(
                                                check,
                                                true
                                        )).toList())
        ));

        ExecutorService executor = Executors.newFixedThreadPool(concurrencyDegree);
        CompletionService<Void> completionService = new ExecutorCompletionService<>(executor);

        AtomicInteger runningTasks = new AtomicInteger(0);

        submitTraverseTasks(traversalState, traversalParams, completionService, runningTasks);

        try {
            while (runningTasks.get() > 0) {
                completionService.take(); // wait for a task to finish
                runningTasks.decrementAndGet();

                submitTraverseTasks(traversalState, traversalParams, completionService, runningTasks);
            }
        } catch (InterruptedException e) {
            log.warn(e.getMessage());
            Thread.currentThread().interrupt();
        } finally {
            executor.shutdown();
        }

        return new TraversalResults(traversalState.results.stream().toList(), traversalState.errors);
    }

    private void submitTraverseTasks(
            TraversalState traversalState,
            TraversalParams traversalParams,
            CompletionService<Void> completionService,
            AtomicInteger runningTasks
    ) {
        ItemToTraverse next;
        while (runningTasks.get() < concurrencyDegree && (next = pollNextToTraverse(traversalState)) != null) {
            final ItemToTraverse finalNext = next;
            if (!tryMarkAsProcessing(finalNext, traversalState, false)) {
                continue;
            }
            runningTasks.incrementAndGet();
            completionService.submit(() -> {
                QualifiedName referencedBundleId = finalNext.bundleId;
                QualifiedName preferredBundleId = getPreferredVersion(finalNext, traversalParams, traversalState);
                finalNext.bundleId = preferredBundleId;
                if (tryMarkAsProcessing(finalNext, traversalState, true)) {
                    traverseItem(finalNext, traversalState, traversalParams);
                    markFinishedTraversing(
                            new Connection(referencedBundleId, finalNext.connectorId),
                            new Connection(preferredBundleId, finalNext.connectorId),
                            traversalState
                    );
                }
                return null;
            });
        }
    }

    private void traverseItem(
            ItemToTraverse itemToTraverse,
            TraversalState traversalState,
            TraversalParams traversalParams
    ) {
        log.info(
                "Started processing bundle {} from connector {}",
                itemToTraverse.bundleId.getUri(),
                itemToTraverse.connectorId.getUri()
        );

        try {
            BundleQueryResultDTO queryResult = provServiceAPI.fetchBundleQueryResult(
                    itemToTraverse.provServiceUri,
                    itemToTraverse.bundleId,
                    itemToTraverse.connectorId,
                    traversalParams.authorizationHeader,
                    traversalParams.querySpecification
            );

            BundleQueryResultDTO findConnectorsResult = provServiceAPI.fetchBundleConnectors(
                    itemToTraverse.provServiceUri,
                    itemToTraverse.bundleId,
                    itemToTraverse.connectorId,
                    traversalParams.authorizationHeader,
                    traversalParams.traverseBackwards
            );

            boolean hasIntegrity = hasIntegrity(itemToTraverse.bundleId, queryResult, findConnectorsResult);

            List<Map.Entry<EValidityCheck, Boolean>> validityChecks =
                    evaluateValidityChecks(traversalParams.validityChecks, itemToTraverse, queryResult);

            ResultFromBundle newResult = convertToNewResult(itemToTraverse, queryResult, hasIntegrity, validityChecks);
            if (newResult != null) {
                traversalState.results.add(newResult);
                log.info(
                        "In bundle {} found query result: {}",
                        itemToTraverse.bundleId.getUri(),
                        newResult.result.toString()
                );
            }

            List<ItemToTraverse> newItemsToTraverse =
                    convertToNewItemsToTraverse(itemToTraverse, findConnectorsResult, hasIntegrity, validityChecks);
            traversalState.toTraverseQueue.addAll(newItemsToTraverse);
            log.info(
                    "In bundle {} found connections to: {}",
                    itemToTraverse.bundleId.getUri(),
                    newItemsToTraverse.stream().map(item -> item.bundleId.getUri()).collect(Collectors.joining(", "))
            );


        } catch (Exception e) {
            String errorMessage =
                    "Error while processing bundle: " + itemToTraverse.bundleId.getUri() + ", error: " + e.getMessage();
            log.error(errorMessage);
            traversalState.errors.add(errorMessage);
        } finally {
            log.info("Finished processing bundle: {}", itemToTraverse.bundleId.getUri());
        }
    }

    private ItemToTraverse pollNextToTraverse(TraversalState traversalState) {
        ItemToTraverse itemToTraverse = traversalState.toTraverseQueue.poll();
        if (itemToTraverse == null) return null;

        // wait until all bundles with higher priority are processed, because they might add higher priority items to traverse
        if (traversalState.traversingReferenced.values().stream()
                .anyMatch(item -> traversalState.toTraverseQueue.comparator().compare(item, itemToTraverse) < 0)) {
            traversalState.toTraverseQueue.add(itemToTraverse); // put back, try to traverse later
            return null;
        }
        if (traversalState.traversingPreferred.values().stream()
                .anyMatch(item -> traversalState.toTraverseQueue.comparator().compare(item, itemToTraverse) < 0)) {
            traversalState.toTraverseQueue.add(itemToTraverse); // put back, try to traverse later
            return null;
        }

        return itemToTraverse;
    }

    private QualifiedName getPreferredVersion(
            ItemToTraverse itemToTraverse,
            TraversalParams traversalParams,
            TraversalState traversalState
    ) {
        try {
            log.info(
                    "Fetching preferred version for bundle: {} with preference: {}",
                    itemToTraverse.bundleId.getUri(),
                    traversalParams.versionPreference
            );
            QualifiedName preferredVersion = provServiceAPI.fetchPreferredBundleVersion(
                    itemToTraverse.provServiceUri,
                    itemToTraverse.bundleId,
                    itemToTraverse.metaBundleId,
                    traversalParams.authorizationHeader,
                    traversalParams.versionPreference
            );
            if (preferredVersion != null) {
                log.info(
                        "Fetch preferred version for bundle: {} returned {}",
                        itemToTraverse.bundleId.getUri(),
                        preferredVersion.getUri()
                );
                return preferredVersion;
            } else {
                log.warn("Fetch preferred version for bundle: {} returned null", itemToTraverse.bundleId.getUri());
            }
        } catch (Exception e) {
            String errorMessage =
                    "Error while fetching preferred version for bundle " + itemToTraverse.bundleId.getUri() + ": " + e;
            traversalState.errors.add(errorMessage);
            log.error(errorMessage);
        }

        return itemToTraverse.bundleId;
    }

    private boolean tryMarkAsProcessing(
            ItemToTraverse itemToTraverse,
            TraversalState traversalState,
            boolean isPreferredVersion
    ) {
        Map<Connection, ItemToTraverse> traversing =
                isPreferredVersion ? traversalState.traversingPreferred : traversalState.traversingReferenced;
        Set<Connection> visited =
                isPreferredVersion ? traversalState.traversedPreferred : traversalState.traversedReferenced;
        String messageExtension = isPreferredVersion ? "" : "preferred version of ";
        Connection connection = new Connection(itemToTraverse.bundleId, itemToTraverse.connectorId);
        if (traversing.putIfAbsent(connection, itemToTraverse) == null) {
            if (!visited.contains(connection)) {
                return true;
            } else {
                traversing.remove(connection, itemToTraverse);
                log.info("Already traversed {}bundle: {}", messageExtension, itemToTraverse.bundleId.getUri());
            }
        } else {
            log.info("Already traversing {}bundle: {}", messageExtension, itemToTraverse.bundleId.getUri());
        }

        return false;
    }

    private void markFinishedTraversing(
            Connection referencedConnection,
            Connection preferredConnection,
            TraversalState traversalState
    ) {
        traversalState.traversedReferenced.add(referencedConnection);
        traversalState.traversedPreferred.add(preferredConnection);
        traversalState.traversingReferenced.remove(referencedConnection);
        traversalState.traversingPreferred.remove(preferredConnection);
    }

    private boolean hasIntegrity(
            QualifiedName bundleId,
            BundleQueryResultDTO queryResult,
            BundleQueryResultDTO findConnectorsResult
    ) {
        if (queryResult == null || findConnectorsResult == null) {
            return false;
        }
        return integrityVerifier.verifyIntegrity(bundleId, queryResult.token) &&
                integrityVerifier.verifyIntegrity(bundleId, findConnectorsResult.token);
    }

    private List<Map.Entry<EValidityCheck, Boolean>> evaluateValidityChecks(
            List<EValidityCheck> validityChecks,
            ItemToTraverse itemTraversed,
            BundleQueryResultDTO queryResult
    ) {
        List<Map.Entry<EValidityCheck, Boolean>> validityCheckValues = new ArrayList<>();
        for (EValidityCheck validityCheck : validityChecks) {
            IValidityVerifier verifier = validityVerifiers.get(validityCheck);
            if (verifier != null) {
                boolean result = verifier.verify(itemTraversed, queryResult);
                validityCheckValues.add(new AbstractMap.SimpleImmutableEntry<>(validityCheck, result));
            } else {
                String errorMessage = "No validity checker registered for: " + validityCheck;
                log.error(errorMessage);
                throw new UnsupportedValidityCheckException(errorMessage);
            }
        }
        return validityCheckValues;
    }

    private ResultFromBundle convertToNewResult(
            ItemToTraverse itemTraversed,
            BundleQueryResultDTO queryResult,
            boolean integrity,
            List<Map.Entry<EValidityCheck, Boolean>> validityChecks
    ) {
        if (omitEmptyResults) {
            if (queryResult == null || queryResult.result == null || queryResult.result.isNull()) {
                log.info("Omitted null result from {}", itemTraversed.bundleId.getUri());
                return null;
            }

            if (queryResult.result.isObject() && queryResult.result.isEmpty() ||
                    queryResult.result.isArray() && queryResult.result.isEmpty()) {
                log.info("Omitted empty result from {}", itemTraversed.bundleId.getUri());
                return null;
            }
        }

        return new ResultFromBundle(
                itemTraversed.bundleId,
                itemTraversed.connectorId,
                queryResult.result,
                integrity,
                validityChecks,
                itemTraversed.pathIntegrity,
                itemTraversed.pathValidityChecks
        );
    }

    private List<ItemToTraverse> convertToNewItemsToTraverse(
            ItemToTraverse itemTraversed,
            BundleQueryResultDTO findConnectorsResult,
            boolean integrity,
            List<Map.Entry<EValidityCheck, Boolean>> validityChecks
    ) {
        if (findConnectorsResult == null || findConnectorsResult.result == null ||
                findConnectorsResult.result.isNull()) {
            log.warn("Find connectors in bundle {} returned null", itemTraversed.bundleId.getUri());
            return new ArrayList<>();
        }

        List<ConnectorDTO> connectors;
        try {
            connectors = new ObjectMapper().convertValue(
                    findConnectorsResult.result, new TypeReference<List<ConnectorDTO>>() {
                    }
            );
        } catch (Exception e) {
            log.error("While converting connectors from bundle {} got error: {}", itemTraversed.bundleId.getUri(), e);
            return new ArrayList<>();
        }

        List<ItemToTraverse> newItemsToTraverse = new ArrayList<>();

        for (ConnectorDTO connector : connectors) {
            if (connector == null || connector.referencedBundleId == null) continue;

            newItemsToTraverse.add(new ItemToTraverse(
                    connector.referencedBundleId.toQN(),
                    connector.referencedConnectorId.toQN(),
                    connector.referencedMetaBundleId != null ? connector.referencedMetaBundleId.toQN() : null,
                    getProvServiceUri(connector, provServiceTable, preferProvServiceFromConnectors),
                    itemTraversed.pathIntegrity && integrity,
                    combineValidityChecks(itemTraversed.pathValidityChecks, validityChecks)
            ));
        }

        return newItemsToTraverse;
    }

    private String getProvServiceUri(
            ConnectorDTO connector,
            IProvServiceTable provServiceTable,
            boolean preferProvServiceFromConnectors
    ) {
        String fromTable = provServiceTable.getServiceUri(connector.referencedBundleId.toQN().getUri());
        String fromConnector = connector.provenanceServiceUri;

        if (preferProvServiceFromConnectors) {
            return fromConnector != null ? fromConnector : fromTable;
        } else {
            return fromTable != null ? fromTable : fromConnector;
        }
    }

    private List<Map.Entry<EValidityCheck, Boolean>> combineValidityChecks(
            List<Map.Entry<EValidityCheck, Boolean>> first,
            List<Map.Entry<EValidityCheck, Boolean>> second
    ) {
        List<Map.Entry<EValidityCheck, Boolean>> combined = new ArrayList<>();

        for (Map.Entry<EValidityCheck, Boolean> firstCheck : first) {
            EValidityCheck key = firstCheck.getKey();
            Boolean firstValue = firstCheck.getValue();
            Boolean secondValue = second.stream().filter(entry -> entry.getKey() == firstCheck.getKey()).findFirst()
                    .map(Map.Entry::getValue).orElse(false); // default to false if not found

            combined.add(new AbstractMap.SimpleImmutableEntry<>(key, firstValue && secondValue));
        }
        return combined;
    }
}
