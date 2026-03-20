package cz.muni.xmichalk.querySpecification.findable;

import cz.muni.fi.cpm.model.CpmDocument;
import cz.muni.fi.cpm.model.IEdge;
import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.TestDocumentProvider;
import cz.muni.xmichalk.models.EdgeToNode;
import cz.muni.xmichalk.models.SubgraphWrapper;
import cz.muni.xmichalk.querySpecification.ICondition;
import org.junit.jupiter.api.Test;
import org.openprovenance.prov.model.StatementOrBundle;
import org.openprovenance.prov.vanilla.QualifiedName;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

import static cz.muni.xmichalk.util.NameSpaceConstants.BLANK_URI;

public class FittingLinearSubgraphsTest {

    @Test public void testFind_fromStartNode_length2() {
        CpmDocument cpmDocument = TestDocumentProvider.samplingBundle_V1;
        QualifiedName startNodeId =
                new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "StoredSampleCon_r1_Spec", null);
        SubgraphWrapper graph = new SubgraphWrapper(cpmDocument.getNodes(), cpmDocument.getEdges());
        INode startNode = cpmDocument.getNode(startNodeId);
        List<ICondition<EdgeToNode>> subgraphParts = List.of(_ -> true, _ -> true);
        FittingLinearSubgraphs fittingLinearSubgraphs = new FittingLinearSubgraphs(
                subgraphParts,
                                                                                   (g, n) -> List.of(new SubgraphWrapper(
                                                                                           List.of(n),
                                                                                           new ArrayList<>()
                                                                                   ))
        );

        List<SubgraphWrapper> results = fittingLinearSubgraphs.find(graph, startNode);

        assert results.size() == startNode.getAllEdges().size();
        assert results.stream()
                .allMatch(subgraph -> subgraph.getNodes().size() == 2 && subgraph.getEdges().size() == 1);
    }

    @Test public void testFind_anywhere_derivation3() {
        CpmDocument cpmDocument = TestDocumentProvider.speciesIdentificationBundle_V0;
        SubgraphWrapper graph = new SubgraphWrapper(cpmDocument.getNodes(), cpmDocument.getEdges());
        INode startNode = cpmDocument.getMainActivity();
        Predicate<IEdge> isDerivation = (edge) -> edge.getRelations().stream()
                .anyMatch(relation -> relation.getKind().equals(StatementOrBundle.Kind.PROV_DERIVATION));
        List<ICondition<EdgeToNode>> subgraphParts = List.of(
                edgeToNode -> true,
                edgeToNode -> isDerivation.test(edgeToNode.edge),
                edgeToNode -> isDerivation.test(edgeToNode.edge)
        );
        FittingLinearSubgraphs fittingLinearSubgraphs = new FittingLinearSubgraphs(subgraphParts, (g, n) -> List.of(g));

        List<SubgraphWrapper> results = fittingLinearSubgraphs.find(graph, startNode);

        assert results.size() % 2 == 0; // same subgraph from both directions
        assert !results.isEmpty();
        assert results.stream()
                .allMatch(subgraph -> subgraph.getNodes().size() == 3 && subgraph.getEdges().size() == 2 &&
                        subgraph.getEdges().stream().allMatch(isDerivation));
    }
}
