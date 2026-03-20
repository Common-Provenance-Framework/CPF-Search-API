package cz.muni.xmichalk.util;

import cz.muni.fi.cpm.model.CpmDocument;
import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.TestDocumentProvider;
import cz.muni.xmichalk.models.EdgeToNode;
import org.junit.jupiter.params.ParameterizedTest;
import org.openprovenance.prov.vanilla.QualifiedName;

import java.util.HashSet;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Stream;

import static cz.muni.xmichalk.util.NameSpaceConstants.BLANK_URI;

public class GraphTraverserTest {

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams") void testTraverseFrom_unfiltered(CpmDocument document,
                                                                                                                      QualifiedName startNodeId
    ) {
        INode startNode = document.getNode(startNodeId);
        Predicate<EdgeToNode> filter = null;
        Set<INode> traversed = new HashSet<>();
        int countOfNodesWithEdges =
                (int) document.getNodes().stream().filter(node -> !node.getAllEdges().isEmpty()).count();

        GraphTraverser.traverseFrom(startNode, edgeToNode -> traversed.add(edgeToNode.node), filter);

        assert (traversed.size() == countOfNodesWithEdges);
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams") void testTraverseFrom_filtered(CpmDocument document,
                                                                                                                    QualifiedName startNodeId
    ) {
        INode startNode = document.getNode(startNodeId);
        Predicate<INode> nodeCondition = node -> node == startNode;
        Predicate<EdgeToNode> filter = (edgeToNode) -> nodeCondition.test(edgeToNode.node);
        Set<INode> traversed = new HashSet<>();

        GraphTraverser.traverseFrom(startNode, edgeToNode -> traversed.add(edgeToNode.node), filter);

        assert (traversed.size() == 1);
        assert traversed.stream().findFirst().get() == startNode;
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams")
    void testTraverseFrom_filteredToNothing(CpmDocument document, QualifiedName startNodeId) {
        INode startNode = document.getNode(startNodeId);
        Predicate<EdgeToNode> filter = (_) -> false;
        Set<INode> traversed = new HashSet<>();

        GraphTraverser.traverseFrom(startNode, edgeToNode -> traversed.add(edgeToNode.node), filter);

        assert (traversed.isEmpty());
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams")
    void testTraverseAndFindNodes_unfiltered(CpmDocument document, QualifiedName startNodeId) {
        INode startNode = document.getNode(startNodeId);
        int countOfNodesWithEdges =
                (int) document.getNodes().stream().filter(node -> !node.getAllEdges().isEmpty()).count();

        Set<INode> filteredNodes = GraphTraverser.traverseAndFindNodes(startNode, (_) -> true);

        assert (filteredNodes.size() == countOfNodesWithEdges);
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams")
    void testTraverseAndFindNodes_filtered(CpmDocument document, QualifiedName startNodeId) {
        INode startNode = document.getNode(startNodeId);
        Predicate<INode> nodeCondition = node -> node == startNode;

        Set<INode> filteredNodes = GraphTraverser.traverseAndFindNodes(startNode, nodeCondition);

        assert (filteredNodes.size() == 1);
        assert filteredNodes.stream().findFirst().get() == startNode;
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams")
    void testTraverseAndFindNodes_filteredToNothing(CpmDocument document, QualifiedName startNodeId) {
        INode startNode = document.getNode(startNodeId);
        Predicate<INode> filter = (_) -> false;

        Set<INode> filteredNodes = GraphTraverser.traverseAndFindNodes(startNode, filter);

        assert (filteredNodes.isEmpty());
    }


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
}
