package cz.muni.xmichalk.util;

import cz.muni.fi.cpm.model.CpmDocument;
import cz.muni.fi.cpm.model.IEdge;
import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.TestDocumentProvider;
import cz.muni.xmichalk.models.EdgeToNode;
import cz.muni.xmichalk.models.SubgraphWrapper;
import org.junit.jupiter.api.Test;
import org.openprovenance.prov.model.StatementOrBundle;
import org.openprovenance.prov.vanilla.QualifiedName;

import java.util.HashSet;
import java.util.List;
import java.util.function.Predicate;

import static cz.muni.xmichalk.util.NameSpaceConstants.BLANK_URI;

public class LinearSubgraphFinderTest {
    @Test public void testFindFrom_found2() {
        CpmDocument cpmDocument = TestDocumentProvider.samplingBundle_V1;
        QualifiedName startNodeId =
                new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "StoredSampleCon_r1", null);
        INode startNode = cpmDocument.getNode(startNodeId);
        Predicate<IEdge> isSpecialization = (edge) -> edge.getRelations().stream()
                .anyMatch(relation -> relation.getKind().equals(StatementOrBundle.Kind.PROV_SPECIALIZATION));
        List<Predicate<EdgeToNode>> subgraph =
                List.of(edgeToNode -> true, edgeToNode -> isSpecialization.test(edgeToNode.edge));

        List<SubgraphWrapper> foundSubgraphs = LinearSubgraphFinder.findSubgraphsFrom(startNode, subgraph);

        assert foundSubgraphs.size() == 2;
        for (SubgraphWrapper foundSubgraph : foundSubgraphs) {
            assert foundSubgraph.getNodes().size() == 2;
            assert foundSubgraph.getEdges().size() == 1;
            List<INode> nodes = foundSubgraph.getNodes();
            assert nodes.get(0) == startNode;
            assert nodes.get(1) != startNode;
            assert isSpecialization.test(foundSubgraph.getEdges().getFirst());
        }
    }

    @Test public void testFindFrom_findLong() {
        CpmDocument cpmDocument = TestDocumentProvider.samplingBundle_V1;
        QualifiedName startNodeId =
                new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "StoredSampleCon_r1", null);
        INode startNode = cpmDocument.getNode(startNodeId);
        List<Predicate<EdgeToNode>> subgraph = List.of(
                edgeToNode -> true,
                edgeToNode -> true,
                edgeToNode -> true,
                edgeToNode -> true,
                edgeToNode -> true,
                edgeToNode -> true
        );

        List<SubgraphWrapper> foundSubgraphs = LinearSubgraphFinder.findSubgraphsFrom(startNode, subgraph);

        assert foundSubgraphs.size() > 1;
        for (SubgraphWrapper foundSubgraph : foundSubgraphs) {
            assert new HashSet<>(foundSubgraph.getNodes()).size() == subgraph.size();
            assert new HashSet<>(foundSubgraph.getEdges()).size() == subgraph.size() - 1;
            assert foundSubgraph.getNodes().getFirst() == startNode;
        }
    }

    @Test public void testFindFrom_found0() {
        CpmDocument cpmDocument = TestDocumentProvider.samplingBundle_V1;
        QualifiedName startNodeId =
                new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "StoredSampleCon_r1", null);
        INode startNode = cpmDocument.getNode(startNodeId);
        List<Predicate<EdgeToNode>> subgraph = List.of(edgeToNode -> false, edgeToNode -> true, edgeToNode -> true);

        List<SubgraphWrapper> foundSubgraphs = LinearSubgraphFinder.findSubgraphsFrom(startNode, subgraph);

        assert foundSubgraphs.isEmpty();
    }

    @Test public void testFindFrom_nullNode() {
        INode startNode = null;
        List<Predicate<EdgeToNode>> subgraph = List.of(edgeToNode -> true, edgeToNode -> true, edgeToNode -> true);

        List<SubgraphWrapper> foundSubgraphs = LinearSubgraphFinder.findSubgraphsFrom(startNode, subgraph);

        assert foundSubgraphs.isEmpty();
    }
}
