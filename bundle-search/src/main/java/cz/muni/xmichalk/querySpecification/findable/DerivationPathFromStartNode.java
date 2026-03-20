package cz.muni.xmichalk.querySpecification.findable;

import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.models.EdgeToNode;
import cz.muni.xmichalk.models.SubgraphWrapper;
import cz.muni.xmichalk.querySpecification.ICondition;
import cz.muni.xmichalk.querySpecification.logicalOperations.AnyTrue;
import cz.muni.xmichalk.querySpecification.subgraphConditions.EdgeToNodeCondition;
import cz.muni.xmichalk.querySpecification.subgraphConditions.edgeConditions.IsRelation;
import org.openprovenance.prov.model.StatementOrBundle;

import java.util.List;

public class DerivationPathFromStartNode implements IFindableSubgraph {
    public Boolean backward;

    public DerivationPathFromStartNode() {
    }

    public DerivationPathFromStartNode(Boolean backward) {
        this.backward = backward;
    }

    @Override public List<SubgraphWrapper> find(final SubgraphWrapper graph, final INode startNode) {
        IFindableSubgraph finder = new FilteredSubgraphs(getDerivationPathCondition(backward), new StartNode());

        return finder.find(graph, startNode);
    }

    public static ICondition<EdgeToNode> getDerivationPathCondition(Boolean backward) {
        return new AnyTrue<>(List.of(
                new EdgeToNodeCondition(
                        new IsRelation(StatementOrBundle.Kind.PROV_DERIVATION),
                        null,
                        backward == null ? null : !backward
                ), new EdgeToNodeCondition(new IsRelation(StatementOrBundle.Kind.PROV_SPECIALIZATION), null, null)
        ));
    }
}
