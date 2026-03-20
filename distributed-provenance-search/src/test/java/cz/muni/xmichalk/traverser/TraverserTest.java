package cz.muni.xmichalk.traverser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import cz.muni.xmichalk.TestBundleData;
import cz.muni.xmichalk.dto.BundleQueryResultDTO;
import cz.muni.xmichalk.dto.ConnectorDTO;
import cz.muni.xmichalk.dto.QualifiedNameDTO;
import cz.muni.xmichalk.dto.token.Token;
import cz.muni.xmichalk.integrity.IIntegrityVerifier;
import cz.muni.xmichalk.models.ItemToTraverse;
import cz.muni.xmichalk.models.TraversalParams;
import cz.muni.xmichalk.models.TraversalResults;
import cz.muni.xmichalk.provServiceAPI.IProvServiceAPI;
import cz.muni.xmichalk.provServiceTable.IProvServiceTable;
import cz.muni.xmichalk.traversalPriority.ETraversalPriority;
import cz.muni.xmichalk.traversalPriority.IntegrityThenOrderedValidity;
import cz.muni.xmichalk.validity.EValidityCheck;
import cz.muni.xmichalk.validity.IValidityVerifier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.openprovenance.prov.model.QualifiedName;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.function.BiPredicate;
import java.util.stream.Stream;

public class TraverserTest {
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final String EXAMPLE_NAMESPACE_URI = "http://example.org/";
    private static final String EXAMPLE_PREFIX = "example";

    private static final QualifiedName bundleA = getExampleQN("bundleA");
    private static final QualifiedName bundleA_new = getExampleQN("bundleA_new");
    private static final QualifiedName bundleB = getExampleQN("bundleB");
    private static final QualifiedName bundleC = getExampleQN("bundleC");
    private static final QualifiedName bundleD = getExampleQN("bundleD");


    private static final QualifiedName connA = getExampleQN("connA");
    private static final QualifiedName connA1 = getExampleQN("connA1");
    private static final QualifiedName connA2 = getExampleQN("connA2");
    private static final QualifiedName connB = getExampleQN("connB");
    private static final QualifiedName connB1 = getExampleQN("connB1");
    private static final QualifiedName connC = getExampleQN("connC");
    private static final QualifiedName connC1 = getExampleQN("connC1");
    private static final QualifiedName connD = getExampleQN("connD");

    private static final Map<String, TestBundleData> testDataSet1 = Map.of( // Diamond branching, 2 versions of bundle A
                                                                            bundleA.getUri(), new TestBundleData(
                    bundleA,
                    bundleA_new,
                    objectMapper.valueToTree("bundleA_result"),
                    List.of(),
                    List.of(getConnectorData(connA, connA, null))
            ), bundleA_new.getUri(), new TestBundleData(
                    bundleA_new, bundleA_new, objectMapper.valueToTree("bundleA_new_result"), List.of(), List.of(
                    getConnectorData(connA, connA, null),
                    getConnectorData(connA1, connA, bundleB),
                    getConnectorData(connA2, connA, bundleC)
            )
            ), bundleB.getUri(), new TestBundleData(
                    bundleB,
                    bundleB,
                    objectMapper.valueToTree("bundleB_result"),
                    List.of(getConnectorData(connA, connA, bundleA)),
                    List.of(getConnectorData(connB, connB, null), getConnectorData(connB1, connB, bundleD))
            ), bundleC.getUri(), new TestBundleData(
                    bundleC,
                    bundleC,
                    objectMapper.valueToTree("bundleC_result"),
                    List.of(getConnectorData(connA, connA, bundleA)),
                    List.of(getConnectorData(connC, connC, null), getConnectorData(connC1, connC, bundleD))
            ), bundleD.getUri(), new TestBundleData(
                    bundleD,
                    bundleD,
                    objectMapper.valueToTree("bundleD_result"),
                    List.of(getConnectorData(connB, connB, bundleB), getConnectorData(connC, connC, bundleC)),
                    List.of(getConnectorData(connD, connD, null))
            )
    );

    private static final Map<String, TestBundleData> testDataSet2 = Map.of( // linear with jump connector from B to D
                                                                            bundleA.getUri(), new TestBundleData(
                    bundleA,
                    bundleA,
                    objectMapper.valueToTree("bundleA_result"),
                    List.of(),
                    List.of(getConnectorData(connA, connA, null), getConnectorData(connA1, connA, bundleB))
            ), bundleB.getUri(), new TestBundleData(
                    bundleB,
                    bundleB,
                    objectMapper.valueToTree("bundleB_result"),
                    List.of(getConnectorData(connA, connA, bundleA)),
                    List.of(
                            getConnectorData(connB, connB, null),
                            getConnectorData(connB1, connB, bundleC),
                            getConnectorData(connC, connC, null),
                            getConnectorData(connC1, connC, bundleD)
                    )
            ), bundleC.getUri(), new TestBundleData(
                    bundleC,
                    bundleC,
                    objectMapper.valueToTree("bundleC_result"),
                    List.of(getConnectorData(connB, connB, bundleB)),
                    List.of(getConnectorData(connC, connC, null), getConnectorData(connC1, connC, bundleD))
            ), bundleD.getUri(), new TestBundleData(
                    bundleD,
                    bundleD,
                    objectMapper.valueToTree("bundleD_result"),
                    List.of(getConnectorData(connC, connC, bundleC)),
                    List.of(getConnectorData(connD, connD, null))
            )
    );

    private static QualifiedName getExampleQN(String localName) {
        return new org.openprovenance.prov.vanilla.QualifiedName(EXAMPLE_NAMESPACE_URI, localName, EXAMPLE_PREFIX);
    }

    private static ConnectorDTO getConnectorData(
            QualifiedName connId,
            QualifiedName referencedConnId,
            QualifiedName referencedBundleId
    ) {
        return new ConnectorDTO(
                new QualifiedNameDTO().from(connId),
                new QualifiedNameDTO().from(referencedConnId),
                new QualifiedNameDTO().from(referencedBundleId),
                referencedBundleId == null ?
                        null :
                        new QualifiedNameDTO().from(getExampleQN("meta_" + referencedBundleId.getLocalPart())),
                "hashA",
                "SHA-256",
                "http://provservice.com/"
        );
    }

    private static IProvServiceTable getMockedProvServiceTable() {
        return (bundleUri) -> "http://provService.com/".concat(bundleUri);
    }

    private static IProvServiceAPI getMockedProvServiceAPI(Map<String, TestBundleData> testData) {
        return new IProvServiceAPI() {
            @Override public BundleQueryResultDTO fetchBundleQueryResult(
                    final String serviceUri,
                    final QualifiedName bundleId,
                    final QualifiedName connectorId,
                    String authorizationHeader,
                    final JsonNode querySpecification
            ) {
                return new BundleQueryResultDTO(new Token(null, "x"), testData.get(bundleId.getUri()).queryResult);
            }

            @Override public QualifiedName fetchPreferredBundleVersion(
                    final String serviceUri,
                    final QualifiedName bundleId,
                    final QualifiedName connectorId,
                    String authorizationHeader,
                    final String versionPreference
            ) {
                if (versionPreference.equals("LATEST")) {
                    return testData.get(bundleId.getUri()).latestVersionId;
                }
                return bundleId;
            }

            @Override public BundleQueryResultDTO fetchBundleConnectors(
                    final String serviceUri,
                    final QualifiedName bundleId,
                    final QualifiedName connectorId,
                    String authorizationHeader,
                    final boolean backward
            ) {
                List<ConnectorDTO> connectors = backward ?
                        testData.get(bundleId.getUri()).backwardConnectors :
                        testData.get(bundleId.getUri()).forwardConnectors;

                return new BundleQueryResultDTO(new Token(null, "x"), objectMapper.valueToTree(connectors));
            }
        };
    }

    private static IIntegrityVerifier getMockedIntegrityVerifier(List<QualifiedName> failForBundles) {
        return (bundleId, _) -> failForBundles.stream().noneMatch(b -> b.getUri().equals(bundleId.getUri()));
    }

    private static Map<EValidityCheck, IValidityVerifier> getMockedValidityVerifiers(Map<QualifiedName, EValidityCheck> failForBundles) {
        BiPredicate<QualifiedName, EValidityCheck> validate =
                (QualifiedName bundleId, EValidityCheck validityCheck) -> failForBundles.entrySet().stream()
                        .noneMatch(e -> e.getKey().getUri().equals(bundleId.getUri()) && e.getValue() == validityCheck);

        return Map.of(
                EValidityCheck.DEMO_SIMPLE_CONSTRAINTS,
                (itemToTraverse, _) -> validate.test(itemToTraverse.bundleId, EValidityCheck.DEMO_SIMPLE_CONSTRAINTS),
                EValidityCheck.DEMO_IS_SAMPLING_BUNDLE,
                (itemToTraverse, _) -> validate.test(itemToTraverse.bundleId, EValidityCheck.DEMO_IS_SAMPLING_BUNDLE),
                EValidityCheck.DEMO_IS_PROCESSING_BUNDLE,
                (itemToTraverse, _) -> validate.test(itemToTraverse.bundleId, EValidityCheck.DEMO_IS_PROCESSING_BUNDLE)
        );
    }

    private static Map<ETraversalPriority, Comparator<ItemToTraverse>> getMockedPriorityComparators() {
        return Map.of(ETraversalPriority.INTEGRITY_THEN_ORDERED_VALIDITY_CHECKS, new IntegrityThenOrderedValidity());
    }

    static Stream<Object[]> bothDirectionsPrams() {
        return Stream.of(
                new Object[]{true, bundleD, connD, "LATEST", 4},
                new Object[]{false, bundleA, connA1, "LATEST", 5},
                // D is searched from 2 different connectors

                new Object[]{true, bundleD, connD, "SPECIFIED", 4},
                new Object[]{false, bundleA, connA1, "SPECIFIED", 1},

                new Object[]{true, bundleC, connC, "SPECIFIED", 2},
                new Object[]{false, bundleB, connB1, "LATEST", 2}
        );
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("bothDirectionsPrams")
    public void test_traverseCount(
            boolean backward,
            QualifiedName startBundle,
            QualifiedName startConnector,
            String versionPreference,
            int expectedCount
    ) {
        Traverser traverser = new Traverser(
                getMockedProvServiceTable(),
                getMockedProvServiceAPI(testDataSet1),
                getMockedIntegrityVerifier(List.of()),
                10,
                true,
                true,
                getMockedValidityVerifiers(Map.of()),
                getMockedPriorityComparators()
        );

        TraversalResults results = traverser.traverseChain(
                startBundle, startConnector, new TraversalParams(
                        backward,
                        null,
                        versionPreference,
                        ETraversalPriority.INTEGRITY_THEN_ORDERED_VALIDITY_CHECKS,
                        List.of(EValidityCheck.DEMO_SIMPLE_CONSTRAINTS),
                        null
                )
        );

        assert results.results.size() == expectedCount;
        assert results.results.stream().allMatch(r -> r.integrity);
        assert results.results.stream().allMatch(r -> r.validityChecks.stream().allMatch(Map.Entry::getValue));
        assert results.results.stream().allMatch(r -> r.pathIntegrity);
        assert results.results.stream().allMatch(r -> r.pathValidityChecks.stream().allMatch(Map.Entry::getValue));
        assert results.errors.isEmpty();
    }

    @Test public void test_failedIntegrity() {

        Traverser traverser = new Traverser(
                getMockedProvServiceTable(),
                getMockedProvServiceAPI(testDataSet2),
                getMockedIntegrityVerifier(List.of(bundleC)),
                10,
                true,
                true,
                getMockedValidityVerifiers(Map.of()),
                getMockedPriorityComparators()
        );

        TraversalResults results = traverser.traverseChain(
                bundleA, connA1, new TraversalParams(
                        false,
                        null,
                        "LATEST",
                        ETraversalPriority.INTEGRITY_THEN_ORDERED_VALIDITY_CHECKS,
                        List.of(EValidityCheck.DEMO_SIMPLE_CONSTRAINTS),
                        null
                )
        );

        assert results.results.size() == 4;
        assert results.results.stream().filter(r -> r.integrity).count() == 3;
        assert results.results.stream().allMatch(r -> r.validityChecks.stream().allMatch(Map.Entry::getValue));
        assert results.results.stream().allMatch(r -> r.pathIntegrity);
        assert results.results.stream().allMatch(r -> r.pathValidityChecks.stream().allMatch(Map.Entry::getValue));
        assert results.errors.isEmpty();
    }

    @Test public void test_failedPathIntegrity() {

        Traverser traverser = new Traverser(
                getMockedProvServiceTable(),
                getMockedProvServiceAPI(testDataSet2),
                getMockedIntegrityVerifier(List.of(bundleB)),
                10,
                true,
                true,
                getMockedValidityVerifiers(Map.of()),
                getMockedPriorityComparators()
        );

        TraversalResults results = traverser.traverseChain(
                bundleA, connA1, new TraversalParams(
                        false,
                        null,
                        "LATEST",
                        ETraversalPriority.INTEGRITY_THEN_ORDERED_VALIDITY_CHECKS,
                        List.of(EValidityCheck.DEMO_SIMPLE_CONSTRAINTS),
                        null
                )
        );

        assert results.results.size() == 4;
        assert results.results.stream().filter(r -> r.integrity).count() == 3;
        assert results.results.stream().allMatch(r -> r.validityChecks.stream().allMatch(Map.Entry::getValue));
        assert results.results.stream().filter(r -> r.pathIntegrity).count() == 2;
        assert results.results.stream().allMatch(r -> r.pathValidityChecks.stream().allMatch(Map.Entry::getValue));
        assert results.errors.isEmpty();
    }

    @Test public void test_failedValidity() {
        Traverser traverser = new Traverser(
                getMockedProvServiceTable(),
                getMockedProvServiceAPI(testDataSet1),
                getMockedIntegrityVerifier(List.of()),
                10,
                true,
                true,
                getMockedValidityVerifiers(Map.of(bundleB, EValidityCheck.DEMO_SIMPLE_CONSTRAINTS)),
                getMockedPriorityComparators()
        );

        TraversalResults results = traverser.traverseChain(
                bundleD, connD, new TraversalParams(
                        true,
                        null,
                        "LATEST",
                        ETraversalPriority.INTEGRITY_THEN_ORDERED_VALIDITY_CHECKS,
                        List.of(EValidityCheck.DEMO_SIMPLE_CONSTRAINTS),
                        null
                )
        );

        assert results.results.size() == 4;
        assert results.results.stream().allMatch(r -> r.integrity);
        assert results.results.stream().filter(r -> r.validityChecks.stream().allMatch(Map.Entry::getValue)).count() ==
                3;
        assert results.results.stream().allMatch(r -> r.pathIntegrity);
        assert results.results.stream().allMatch(r -> r.pathValidityChecks.stream().allMatch(Map.Entry::getValue));
        assert results.errors.isEmpty();
    }

    @Test public void test_failedPathValidity() {
        Traverser traverser = new Traverser(
                getMockedProvServiceTable(),
                getMockedProvServiceAPI(testDataSet1),
                getMockedIntegrityVerifier(List.of()),
                10,
                true,
                true,
                getMockedValidityVerifiers(Map.of(
                        bundleB,
                        EValidityCheck.DEMO_SIMPLE_CONSTRAINTS,
                        bundleC,
                        EValidityCheck.DEMO_SIMPLE_CONSTRAINTS
                )),
                getMockedPriorityComparators()
        );

        TraversalResults results = traverser.traverseChain(
                bundleD, connD, new TraversalParams(
                        true,
                        null,
                        "LATEST",
                        ETraversalPriority.INTEGRITY_THEN_ORDERED_VALIDITY_CHECKS,
                        List.of(EValidityCheck.DEMO_SIMPLE_CONSTRAINTS),
                        null
                )
        );

        assert results.results.size() == 4;
        assert results.results.stream().allMatch(r -> r.integrity);
        assert results.results.stream().filter(r -> r.validityChecks.stream().allMatch(Map.Entry::getValue)).count() ==
                2;
        assert results.results.stream().allMatch(r -> r.pathIntegrity);
        assert results.results.stream().filter(r -> r.pathValidityChecks.stream().allMatch(Map.Entry::getValue))
                .count() == 3;
        assert results.errors.isEmpty();
    }
}
