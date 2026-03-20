package cz.muni.xmichalk.querySpecification.findable;

import cz.muni.fi.cpm.model.CpmDocument;
import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.TestDocumentProvider;
import cz.muni.xmichalk.models.SubgraphWrapper;
import cz.muni.xmichalk.querySpecification.ICondition;
import org.junit.jupiter.params.ParameterizedTest;
import org.openprovenance.prov.vanilla.QualifiedName;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static cz.muni.xmichalk.util.NameSpaceConstants.BLANK_URI;

public class FittingNodesTest {
    static Stream<Object[]> testParams() {
        return Stream.of(
                new Object[]{
                        TestDocumentProvider.samplingBundle_V1,
                        new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "StoredSampleCon_r1_Spec", null)
                }, new Object[]{
                        TestDocumentProvider.samplingBundle_V1,
                        new org.openprovenance.prov.vanilla.QualifiedName(
                                BLANK_URI,
                                "StoredSampleCon_r2_3um_Spec",
                                null
                        )
                }, new Object[]{
                        TestDocumentProvider.processingBundle_V1,
                        new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "ProcessedSampleConSpec", null)
                }, new Object[]{
                        TestDocumentProvider.processingBundle_V1,
                        new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "StoredSampleCon_r1", null)
                }
        );
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams") void testFind_anywhere_startNode(CpmDocument document,
                                                                                                                      QualifiedName startNodeId
    ) {
        INode startNode = document.getNode(startNodeId);
        ICondition<INode> nodeCondition = node -> node == startNode;
        SubgraphWrapper graph = new SubgraphWrapper(document.getNodes(), document.getEdges());
        FittingNodes fittingNodes = new FittingNodes(nodeCondition, (g, n) -> List.of(g));

        List<SubgraphWrapper> results = fittingNodes.find(graph, startNode);

        assert results.size() == 1;
        assert results.getFirst().getNodes().size() == 1;
        assert results.getFirst().getNodes().getFirst() == startNode;
        assert results.getFirst().getEdges().isEmpty();
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams") void testFind_anywhere_all(CpmDocument document,
                                                                                                                QualifiedName startNodeId
    ) {
        INode startNode = document.getNode(startNodeId);
        ICondition<INode> nodeCondition = _ -> true;
        SubgraphWrapper graph = new SubgraphWrapper(document.getNodes(), document.getEdges());
        FittingNodes fittingNodes = new FittingNodes(nodeCondition, (g, n) -> List.of(g));

        List<SubgraphWrapper> results = fittingNodes.find(graph, startNode);

        assert results.size() == document.getNodes().size();
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams") void testFind_anywhere_none(CpmDocument document,
                                                                                                                 QualifiedName startNodeId
    ) {
        INode startNode = document.getNode(startNodeId);
        ICondition<INode> nodeCondition = _ -> false;
        SubgraphWrapper graph = new SubgraphWrapper(document.getNodes(), document.getEdges());
        FittingNodes fittingNodes = new FittingNodes(nodeCondition, (g, n) -> List.of(g));

        List<SubgraphWrapper> results = fittingNodes.find(graph, startNode);

        assert results.isEmpty();
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams") void testFind_fromSubgraps_none(CpmDocument document,
                                                                                                                     QualifiedName startNodeId
    ) {
        INode startNode = document.getNode(startNodeId);
        ICondition<INode> nodeCondition = _ -> true;
        SubgraphWrapper graph = new SubgraphWrapper(document.getNodes(), document.getEdges());
        FittingNodes fittingNodes = new FittingNodes(nodeCondition, (_, _) -> new ArrayList<>());

        List<SubgraphWrapper> results = fittingNodes.find(graph, startNode);

        assert results.isEmpty();
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams") void testFind_fromSubgraps_all(CpmDocument document,
                                                                                                                    QualifiedName startNodeId
    ) {
        INode startNode = document.getNode(startNodeId);
        ICondition<INode> nodeCondition = _ -> true;
        SubgraphWrapper graph = new SubgraphWrapper(document.getNodes(), document.getEdges());
        IFindableSubgraph subgraphFinder = (g, _) -> {
            return List.of(
                    new SubgraphWrapper(g.getNodes().subList(0, 5), new ArrayList<>()),
                    new SubgraphWrapper(g.getNodes().subList(5, g.getNodes().size()), new ArrayList<>())
            );
        };
        FittingNodes fittingNodes = new FittingNodes(nodeCondition, subgraphFinder);

        List<SubgraphWrapper> results = fittingNodes.find(graph, startNode);

        assert results.size() == document.getNodes().size();
        assert results.stream().allMatch(subgraphWrapper -> subgraphWrapper.getNodes().size() == 1);
    }
}
