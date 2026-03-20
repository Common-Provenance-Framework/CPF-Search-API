package cz.muni.xmichalk.querySpecification.findable;

import cz.muni.fi.cpm.model.CpmDocument;
import cz.muni.fi.cpm.model.IEdge;
import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.TestDocumentProvider;
import cz.muni.xmichalk.models.SubgraphWrapper;
import org.junit.jupiter.api.Test;
import org.openprovenance.prov.model.QualifiedName;
import org.openprovenance.prov.model.StatementOrBundle;

import java.util.List;
import java.util.function.Predicate;

import static cz.muni.xmichalk.util.NameSpaceConstants.BLANK_URI;

public class FilteredSubgraphsTest {

    private boolean isRelation(IEdge edge, StatementOrBundle.Kind kind) {
        return edge.getRelations().stream().anyMatch(relation -> relation.getKind().equals(kind));
    }

    @Test public void testFind_fromStartNode_derivation() {
        CpmDocument cpmDocument = TestDocumentProvider.speciesIdentificationBundle_V0;
        SubgraphWrapper graph = new SubgraphWrapper(cpmDocument.getNodes(), cpmDocument.getEdges());
        QualifiedName startNodeId =
                new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "IdentifiedSpeciesCon", "blank");
        INode startNode = cpmDocument.getNode(startNodeId);
        Predicate<IEdge> edgeCondition =
                (edge) -> edge == null || isRelation(edge, StatementOrBundle.Kind.PROV_DERIVATION);
        FilteredSubgraphs filteredSubgraphs = new FilteredSubgraphs(
                (edgeToNode) -> edgeCondition.test(edgeToNode.edge),
                (g, n) -> List.of(new SubgraphWrapper(List.of(n), List.of()))
        );

        List<SubgraphWrapper> results = filteredSubgraphs.find(graph, startNode);

        assert results.size() == 1;
        assert results.getFirst().getNodes().size() == 3;
        assert results.getFirst().getEdges().size() == 2;
        assert results.getFirst().getNodes().stream().allMatch(node -> node != null);
        assert results.getFirst().getEdges().stream().allMatch(edge -> edge != null && edgeCondition.test(edge));
    }

    @Test public void testFind_fromForwardConnectors_ConnectorSpecializations() {
        CpmDocument cpmDocument = TestDocumentProvider.samplingBundle_V1;
        SubgraphWrapper graph = new SubgraphWrapper(cpmDocument.getNodes(), cpmDocument.getEdges());
        QualifiedName startNodeId =
                new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "IdentifiedSpeciesCon", "blank");
        INode startNode = cpmDocument.getNode(startNodeId);
        Predicate<IEdge> isSpecialization = (edge) -> isRelation(edge, StatementOrBundle.Kind.PROV_SPECIALIZATION);
        Predicate<IEdge> edgeCondition = (edge) -> edge == null || isSpecialization.test(edge);
        Predicate<INode> nodeCondition = (node) -> cpmDocument.getForwardConnectors().contains(node);
        FilteredSubgraphs filteredSubgraphs = new FilteredSubgraphs(
                (edgeToNode) -> edgeCondition.test(edgeToNode.edge) && nodeCondition.test(edgeToNode.node),
                (g, n) -> List.of(new SubgraphWrapper(cpmDocument.getForwardConnectors(), List.of()))
        );

        List<SubgraphWrapper> results = filteredSubgraphs.find(graph, startNode);

        assert results.size() == cpmDocument.getForwardConnectors().size();
        assert results.stream().allMatch(subgraph -> subgraph.getNodes().size() == 2);
        assert results.getFirst().getNodes().stream().allMatch(node -> nodeCondition.test(node));
        assert results.getFirst().getEdges().stream().allMatch(edge -> edge != null && isSpecialization.test(edge));
    }

}
