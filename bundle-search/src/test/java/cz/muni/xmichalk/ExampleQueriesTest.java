package cz.muni.xmichalk;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import cz.muni.fi.cpm.merged.CpmMergedFactory;
import cz.muni.fi.cpm.model.*;
import cz.muni.fi.cpm.vanilla.CpmProvFactory;
import cz.muni.xmichalk.models.ConnectorData;
import cz.muni.xmichalk.models.DocumentStart;
import cz.muni.xmichalk.models.QualifiedNameData;
import cz.muni.xmichalk.models.QueryContext;
import cz.muni.xmichalk.queries.*;
import cz.muni.xmichalk.querySpecification.ICondition;
import cz.muni.xmichalk.querySpecification.bundleConditions.AllNodes;
import cz.muni.xmichalk.querySpecification.countable.CountComparisonCondition;
import cz.muni.xmichalk.querySpecification.countable.CountConstant;
import cz.muni.xmichalk.querySpecification.countable.EComparisonResult;
import cz.muni.xmichalk.querySpecification.findable.*;
import cz.muni.xmichalk.querySpecification.logicalOperations.AllTrue;
import cz.muni.xmichalk.querySpecification.logicalOperations.AnyTrue;
import cz.muni.xmichalk.querySpecification.logicalOperations.Implication;
import cz.muni.xmichalk.querySpecification.logicalOperations.Negation;
import cz.muni.xmichalk.querySpecification.nodeConditions.*;
import cz.muni.xmichalk.querySpecification.subgraphConditions.EdgeToNodeCondition;
import cz.muni.xmichalk.querySpecification.subgraphConditions.edgeConditions.IsRelation;
import org.junit.jupiter.api.Test;
import org.openprovenance.prov.model.Document;
import org.openprovenance.prov.model.QualifiedName;
import org.openprovenance.prov.model.StatementOrBundle;
import org.openprovenance.prov.model.interop.Formats;
import org.openprovenance.prov.vanilla.ProvFactory;

import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.util.List;

import static cz.muni.xmichalk.util.AttributeNames.*;
import static cz.muni.xmichalk.util.NameSpaceConstants.*;
import static cz.muni.xmichalk.util.ProvDocumentUtils.deserialize;

public class ExampleQueriesTest {
    ProvFactory pF = new ProvFactory();
    ICpmFactory cF = new CpmMergedFactory(pF);
    ICpmProvFactory cPF = new CpmProvFactory(pF);
    ObjectMapper objectMapper = new ObjectMapper();

    @Test public void findDerivationSubgraph() throws IOException {
        CpmDocument cpmDoc = TestDocumentProvider.samplingBundle_V1;
        QualifiedName startNodeId =
                new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "StoredSampleCon_r1_Spec", "blank");

        IQuery<?> query = new GetSubgraphs(new DerivationPathFromStartNode());
        JsonNode serializedQuery = objectMapper.valueToTree(query);
        IQuery<?> deserializedQuery = objectMapper.convertValue(
                serializedQuery, new TypeReference<IQuery<?>>() {
                }
        );
        QueryContext context = new QueryContext(cpmDoc.getBundleId(), startNodeId, null, new MockedStorage());

        Object result = deserializedQuery.evaluate(context).result;

        assert result != null;
        assert result instanceof List<?>;
        List<?> list = (List<?>) result;
        assert (list.size() == 1);
        Object subgraphObject = list.getFirst();
        assert subgraphObject instanceof JsonNode;
        JsonNode subgraphJsonNode = (JsonNode) subgraphObject;
        Document subgraphDoc = deserialize(subgraphJsonNode.toString(), Formats.ProvFormat.JSON);
        assert subgraphDoc != null;
        CpmDocument subgraphCpmDoc = new CpmDocument(subgraphDoc, pF, cPF, cF);
        assert subgraphCpmDoc.getNodes().size() == 5;
        assert subgraphCpmDoc.getEdges().size() == 4;

        for (IEdge edge : subgraphCpmDoc.getEdges()) {
            assert edge.getKind() == StatementOrBundle.Kind.PROV_DERIVATION ||
                    edge.getKind() == StatementOrBundle.Kind.PROV_SPECIALIZATION;
        }
    }

    @Test public void findMainActivityId() throws AccessDeniedException {
        CpmDocument cpmDoc = TestDocumentProvider.processingBundle_V1;
        QualifiedName startNodeId =
                new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "ProcessedSampleConSpec", "blank");
        IQuery<List<QualifiedNameData>> query = new GetNodeIds(new FittingNodes(new HasAttrQualifiedNameValue(
                ATTR_PROV_TYPE.getUri(),
                CPM_URI + "mainActivity"
        )));
        JsonNode serializedSpecification = objectMapper.valueToTree(query);
        IQuery<?> deserializedQuery = objectMapper.convertValue(
                serializedSpecification, new TypeReference<IQuery<?>>() {
                }
        );
        QueryContext context = new QueryContext(cpmDoc.getBundleId(), startNodeId, null, new MockedStorage());

        Object result = deserializedQuery.evaluate(context).result;

        assert result != null;
        assert result instanceof List<?>;
        List<?> foundNodeIds = (List<?>) result;
        assert foundNodeIds.size() == 1;
        QualifiedNameData qnData = (QualifiedNameData) foundNodeIds.getFirst();
        assert qnData.toQN().getUri().equals(cpmDoc.getMainActivity().getId().getUri());
    }

    @Test public void findIdsOfDsConnectorSpecialization() throws AccessDeniedException {
        CpmDocument cpmDoc = TestDocumentProvider.processingBundle_V1;
        QualifiedName startNodeId =
                new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "ProcessedSampleConSpec", "blank");
        IQuery<List<QualifiedNameData>> query = new GetNodeIds(new FittingNodes(
                new Negation<>(new HasAttrQualifiedNameValue(
                        ATTR_PROV_TYPE.getUri(),
                        CPM_URI + "(backward|forward)Connector"
                )),
                new FilteredSubgraphs(
                        new EdgeToNodeCondition(new IsRelation(StatementOrBundle.Kind.PROV_SPECIALIZATION), null, null),
                        new StartNode()
                )

        ));
        JsonNode serializedSpecification = objectMapper.valueToTree(query);
        IQuery<?> deserializedQuery = objectMapper.convertValue(
                serializedSpecification, new TypeReference<IQuery<?>>() {
                }
        );
        QueryContext context = new QueryContext(cpmDoc.getBundleId(), startNodeId, null, new MockedStorage());

        Object result = deserializedQuery.evaluate(context).result;

        assert result != null;
        assert result instanceof List<?>;
        List<?> foundNodeIds = (List<?>) result;
        assert foundNodeIds.size() == 1;
    }

    @Test public void findStoringActivitiesOnUsagePathBackward() throws IOException {
        CpmDocument cpmDoc = TestDocumentProvider.dnaSequencingBundle_V0;
        QualifiedName startNodeId =
                new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "FilteredSequencesCon", "blank");
        IQuery<?> query = new GetNodes(new FittingNodes(
                new AllTrue<>(List.of(
                        new IsKind(StatementOrBundle.Kind.PROV_ACTIVITY),
                        new HasAttrLangStringValue(DCT_URI + "type", null, "(?i).*storing.*")
                )), new FilteredSubgraphs(
                new AnyTrue<>(List.of(
                        new EdgeToNodeCondition(
                                new AnyTrue<>(List.of(
                                        new IsRelation(StatementOrBundle.Kind.PROV_USAGE),
                                        new IsRelation(StatementOrBundle.Kind.PROV_GENERATION)
                                )), null, false
                        ),
                        new EdgeToNodeCondition(new IsRelation(StatementOrBundle.Kind.PROV_SPECIALIZATION), null, null)
                )), new FilteredSubgraphs(
                new EdgeToNodeCondition(
                        new IsRelation(StatementOrBundle.Kind.PROV_DERIVATION),
                        new HasAttrQualifiedNameValue(ATTR_PROV_TYPE.getUri(), CPM_URI + "forwardConnector"),
                        false
                ), new StartNode()
        )
        )
        ));
        JsonNode serializedQuery = objectMapper.valueToTree(query);
        IQuery<?> deserializedQuery = objectMapper.convertValue(
                serializedQuery, new TypeReference<IQuery<?>>() {
                }
        );
        QueryContext context = new QueryContext(cpmDoc.getBundleId(), startNodeId, null, new MockedStorage());

        Object result = deserializedQuery.evaluate(context).result;

        assert result != null;
        JsonNode foundNodesDoc = (JsonNode) result;
        Document resultsDoc = deserialize(foundNodesDoc.toString(), Formats.ProvFormat.JSON);
        assert resultsDoc != null;
        CpmDocument resultsCpmDoc = new CpmDocument(resultsDoc, pF, cPF, cF);
        assert resultsCpmDoc.getNodes().size() == 2;

    }

    @Test public void findActivitiesAssociatedWithJaneSmith() throws IOException {
        CpmDocument cpmDoc = TestDocumentProvider.samplingBundle_V1;
        QualifiedName startNodeId =
                new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "StoredSampleCon_r1_Spec", "blank");
        IQuery<?> query = new GetNodes(new FittingNodes(
                new IsKind(StatementOrBundle.Kind.PROV_ACTIVITY), new FittingLinearSubgraphs(List.of(
                new EdgeToNodeCondition(null, new IsKind(StatementOrBundle.Kind.PROV_ACTIVITY), null),
                new EdgeToNodeCondition(
                        new IsRelation(StatementOrBundle.Kind.PROV_ASSOCIATION), new AllTrue<>(List.of(
                        new HasAttrQualifiedNameValue(ATTR_PROV_TYPE.getUri(), SCHEMA_URI + "Person"),
                        new HasAttrLangStringValue(SCHEMA_URI + "name", null, "Jane Smith")
                )), false
                )
        ))
        ));
        JsonNode serializedQuery = objectMapper.valueToTree(query);
        IQuery<?> deserializedQuery = objectMapper.convertValue(
                serializedQuery, new TypeReference<IQuery<?>>() {
                }
        );
        QueryContext context = new QueryContext(cpmDoc.getBundleId(), startNodeId, null, new MockedStorage());

        Object result = deserializedQuery.evaluate(context).result;


        assert result != null;
        assert result instanceof JsonNode;
        JsonNode foundNodesDoc = (JsonNode) result;
        Document resultsDoc = deserialize(foundNodesDoc.toString(), Formats.ProvFormat.JSON);
        assert resultsDoc != null;
        CpmDocument resultsCpmDoc = new CpmDocument(resultsDoc, pF, cPF, cF);
        assert resultsCpmDoc.getNodes().size() == 2;
    }

    @Test public void findSenderReceiverNodesConnectedToDerivationPath() throws IOException {
        CpmDocument cpmDoc = TestDocumentProvider.samplingBundle_V1;
        QualifiedName startNodeId =
                new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "StoredSampleCon_r1", "blank");
        IQuery<?> query = new GetNodes(new FittingNodes(
                new HasAttrQualifiedNameValue(ATTR_PROV_TYPE.getUri(), CPM_URI + "(sender|receiver)Agent"),
                new FittingLinearSubgraphs(
                        List.of(
                                new EdgeToNodeCondition(null, null, null), new EdgeToNodeCondition(
                                        new IsRelation(StatementOrBundle.Kind.PROV_ATTRIBUTION),
                                        new HasAttrQualifiedNameValue(
                                                ATTR_PROV_TYPE.getUri(),
                                                CPM_URI + "(sender|receiver)Agent"
                                        ),
                                        false

                                )
                        ), new DerivationPathFromStartNode(true)
                )
        ));
        JsonNode serializedSpecification = objectMapper.valueToTree(query);
        IQuery<?> deserializedQuery = objectMapper.convertValue(
                serializedSpecification, new TypeReference<IQuery<?>>() {
                }
        );
        QueryContext context = new QueryContext(cpmDoc.getBundleId(), startNodeId, null, new MockedStorage());

        Object result = deserializedQuery.evaluate(context).result;

        assert result != null;
        assert result instanceof JsonNode;
        JsonNode foundNodesDoc = (JsonNode) result;
        Document resultsDoc = deserialize(foundNodesDoc.toString(), Formats.ProvFormat.JSON);
        assert resultsDoc != null;
        CpmDocument resultsCpmDoc = new CpmDocument(resultsDoc, pF, cPF, cF);
        assert resultsCpmDoc.getNodes().size() == 1;
    }


    @Test public void findUsageGenerationSpecializationSubgraph() throws IOException {
        CpmDocument cpmDoc = TestDocumentProvider.processingBundle_V1;
        QualifiedName startNodeId =
                new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "StoredSampleCon_r1", "blank");
        IQuery<?> query = new GetSubgraphs(new FilteredSubgraphs(
                new AnyTrue<>(List.of(
                        new EdgeToNodeCondition(
                                new AnyTrue<>(List.of(
                                        new IsRelation(StatementOrBundle.Kind.PROV_USAGE),
                                        new IsRelation(StatementOrBundle.Kind.PROV_GENERATION)
                                )), null, true
                        ),
                        new EdgeToNodeCondition(new IsRelation(StatementOrBundle.Kind.PROV_SPECIALIZATION), null, null)
                )), new StartNode()
        ));
        JsonNode serializedQuery = objectMapper.valueToTree(query);
        IQuery<?> deserializedQuery = objectMapper.convertValue(
                serializedQuery, new TypeReference<IQuery<?>>() {
                }
        );
        QueryContext context = new QueryContext(cpmDoc.getBundleId(), startNodeId, null, new MockedStorage());

        Object result = deserializedQuery.evaluate(context).result;

        assert result != null;
        assert result instanceof List<?>;
        List<?> list = (List<?>) result;
        assert (list.size() == 1);
        Object subgraphObject = list.getFirst();
        assert subgraphObject instanceof JsonNode;
        JsonNode subgraphJsonNode = (JsonNode) subgraphObject;
        Document subgraphDoc = deserialize(subgraphJsonNode.toString(), Formats.ProvFormat.JSON);
        assert subgraphDoc != null;
        CpmDocument subgraphCpmDoc = new CpmDocument(subgraphDoc, pF, cPF, cF);
        assert subgraphCpmDoc.getNodes().size() == 7;
        assert subgraphCpmDoc.getEdges().size() == 7;
    }

    @Test public void findFLeeAssociatedActivitiesSubgraphs() throws IOException {
        CpmDocument cpmDoc = TestDocumentProvider.dnaSequencingBundle_V0;
        QualifiedName startNodeId =
                new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "StoredSampleCon_r1", "blank");
        IQuery<?> query = new GetSubgraphs(new FittingLinearSubgraphs(
                List.of(
                        new EdgeToNodeCondition(null, new IsKind(StatementOrBundle.Kind.PROV_ACTIVITY), null),
                        new EdgeToNodeCondition(
                                new IsRelation(StatementOrBundle.Kind.PROV_ASSOCIATION), new AllTrue<>(List.of(
                                new HasAttrQualifiedNameValue(ATTR_PROV_TYPE.getUri(), SCHEMA_URI + "Person"),
                                new HasAttrLangStringValue(SCHEMA_URI + "name", null, "F. Lee")
                        )), false
                        )
                ), new WholeGraph()
        )

        );
        JsonNode serializedQuery = objectMapper.valueToTree(query);
        IQuery<?> deserializedQuery = objectMapper.convertValue(
                serializedQuery, new TypeReference<IQuery<?>>() {
                }
        );
        QueryContext context = new QueryContext(cpmDoc.getBundleId(), startNodeId, null, new MockedStorage());

        Object result = deserializedQuery.evaluate(context).result;

        assert result != null;
        assert result instanceof List<?>;
        List<?> list = (List<?>) result;
        assert (list.size() == 3);
        Object subgraphObject = list.getFirst();
        assert subgraphObject instanceof JsonNode;
        JsonNode subgraphJsonNode = (JsonNode) subgraphObject;
        Document subgraphDoc = deserialize(subgraphJsonNode.toString(), Formats.ProvFormat.JSON);
        assert subgraphDoc != null;
        CpmDocument subgraphCpmDoc = new CpmDocument(subgraphDoc, pF, cPF, cF);
        assert subgraphCpmDoc.getNodes().size() == 2;
        assert subgraphCpmDoc.getEdges().size() == 1;
    }

    @Test public void testFitsSimpleValidityCheck() throws AccessDeniedException {
        CpmDocument cpmDoc = TestDocumentProvider.samplingBundle_V1;
        QualifiedName startNodeId =
                new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "StoredSampleCon_r1_Spec", "blank");
        ICondition<INode> isMainActivity =
                new HasAttrQualifiedNameValue(ATTR_PROV_TYPE.getUri(), CPM_URI + "mainActivity");
        ICondition<INode> hasMetaReference = new HasAttr(ATTR_REFERENCED_META_BUNDLE_ID.getUri());
        ICondition<INode> isBackwardConnector =
                new HasAttrQualifiedNameValue(ATTR_PROV_TYPE.getUri(), CPM_URI + "backwardConnector");
        ICondition<INode> hasBackwardConAttributes = new AllTrue<>(List.of(
                new HasAttr(ATTR_REFERENCED_META_BUNDLE_ID.getUri()),
                new HasAttr(ATTR_REFERENCED_BUNDLE_ID.getUri()),
                new HasAttr(ATTR_REFERENCED_BUNDLE_HASH_VALUE.getUri()),
                new HasAttr(ATTR_HASH_ALG.getUri())
        ));
        IQuery<?> query = new TestBundleFits(new AllTrue<DocumentStart>(List.of(
                // Has exactly one main activity
                new CountComparisonCondition<DocumentStart>(
                        new FittingNodes(isMainActivity),
                        EComparisonResult.EQUALS,
                        new CountConstant<DocumentStart>(1)
                ),
                // Main activity has ref to meta bundle
                new AllNodes(new Implication<INode>(isMainActivity, hasMetaReference)),
                // All backward connectors have necessary attributes specified
                new AllNodes(new Implication<>(isBackwardConnector, hasBackwardConAttributes))
        )));
        JsonNode serializedSpecification = objectMapper.valueToTree(query);
        IQuery<?> deserializedQuery = objectMapper.convertValue(
                serializedSpecification, new TypeReference<IQuery<?>>() {
                }
        );
        QueryContext context = new QueryContext(cpmDoc.getBundleId(), startNodeId, null, new MockedStorage());

        Object result = deserializedQuery.evaluate(context).result;
        assert result != null;
        assert result instanceof Boolean;
        Boolean fits = (Boolean) result;
        assert fits;
    }

    @Test public void testFitsIsSamplingBundle() throws AccessDeniedException {
        CpmDocument cpmDoc = TestDocumentProvider.samplingBundle_V1;
        QualifiedName startNodeId =
                new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "ProcessedSampleConSpec", "blank");
        IQuery<?> query = new TestBundleFits(new CountComparisonCondition<>(
                new FittingNodes(new AllTrue<>(List.of(
                        new HasAttrQualifiedNameValue(
                                ATTR_PROV_TYPE.getUri(),
                                CPM_URI + "mainActivity"
                        ),
                        new HasId("(?i).*Sampling.*")
                ))

                ), EComparisonResult.GREATER_THAN, new CountConstant<>(0)
        ));
        JsonNode serializedSpecification = objectMapper.valueToTree(query);
        IQuery<?> deserializedQuery = objectMapper.convertValue(
                serializedSpecification, new TypeReference<IQuery<?>>() {
                }
        );
        QueryContext context = new QueryContext(cpmDoc.getBundleId(), startNodeId, null, new MockedStorage());

        Object result = deserializedQuery.evaluate(context).result;

        assert result != null;
        assert result instanceof Boolean;
        Boolean fits = (Boolean) result;
        assert fits;
    }

    @Test public void findDerivationpathBackwardConnectors() throws AccessDeniedException {
        CpmDocument cpmDoc = TestDocumentProvider.processingBundle_V1;
        QualifiedName startNodeId =
                new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "ProcessedSampleConSpec", "blank");
        IQuery<?> query = new GetConnectors(true, new DerivationPathFromStartNode(true));
        JsonNode serializedSpecification = objectMapper.valueToTree(query);
        IQuery<?> deserializedQuery = objectMapper.convertValue(
                serializedSpecification, new TypeReference<IQuery<?>>() {
                }
        );
        QueryContext context = new QueryContext(cpmDoc.getBundleId(), startNodeId, null, new MockedStorage());

        Object result = deserializedQuery.evaluate(context).result;

        assert result != null;
        assert result instanceof List;
        List<?> list = (List<?>) result;
        assert list.size() == 1;
        assert list.getFirst() instanceof ConnectorData;
        ConnectorData connectorData = (ConnectorData) list.getFirst();
        assert connectorData.id.toQN().getUri().equals(BLANK_URI + "StoredSampleCon_r1");
    }

    @Test public void findDerivationPathForwardConnectors() throws AccessDeniedException {
        CpmDocument cpmDoc = TestDocumentProvider.samplingBundle_V1;

        QualifiedName startNodeId =
                new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "StoredSampleCon_r1_Spec", "blank");
        IQuery<?> query = new GetConnectors(false, new DerivationPathFromStartNode(false));
        JsonNode serializedSpecification = objectMapper.valueToTree(query);
        IQuery<?> deserializedQuery = objectMapper.convertValue(
                serializedSpecification, new TypeReference<IQuery<?>>() {
                }
        );
        QueryContext context = new QueryContext(cpmDoc.getBundleId(), startNodeId, null, new MockedStorage());

        Object result = deserializedQuery.evaluate(context).result;

        assert result != null;
        assert result instanceof List;
        List<?> list = (List<?>) result;
        assert list.size() == 4;
    }
}
