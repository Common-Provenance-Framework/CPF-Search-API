package cz.muni.xmichalk.querySpecification.subgraphConditions;

import cz.muni.xmichalk.models.EdgeToNode;
import cz.muni.xmichalk.querySpecification.ICondition;
import cz.muni.xmichalk.querySpecification.logicalOperations.AnyTrue;
import cz.muni.xmichalk.querySpecification.subgraphConditions.edgeConditions.IsRelation;
import org.openprovenance.prov.model.StatementOrBundle;

import java.util.List;

public class DerivationPathCondition implements ICondition<EdgeToNode> {
    public Boolean backward;

    public DerivationPathCondition() {
    }

    public DerivationPathCondition(Boolean backward) {
        this.backward = backward;
    }

    public ICondition<EdgeToNode> getCondition(Boolean backward) {
        return new AnyTrue<>(List.of(
                new EdgeToNodeCondition(
                        new IsRelation(StatementOrBundle.Kind.PROV_DERIVATION),
                        null,
                        backward == null ? null : !backward
                ), new EdgeToNodeCondition(new IsRelation(StatementOrBundle.Kind.PROV_SPECIALIZATION), null, null)
        ));
    }

    @Override public boolean test(final EdgeToNode target) {
        return getCondition(backward).test(target);
    }
}
