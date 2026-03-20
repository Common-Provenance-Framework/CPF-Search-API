package cz.muni.xmichalk.querySpecification.subgraphConditions.edgeConditions;

import cz.muni.fi.cpm.model.IEdge;
import cz.muni.xmichalk.querySpecification.ICondition;
import org.openprovenance.prov.model.StatementOrBundle;

public class IsRelation implements ICondition<IEdge> {
    public StatementOrBundle.Kind relation;

    public IsRelation() {
    }

    public IsRelation(StatementOrBundle.Kind relation) {
        this.relation = relation;
    }

    public boolean test(IEdge edge) {
        if (relation == null) {
            throw new IllegalStateException("Value of relation cannot be null in " + this.getClass().getSimpleName());
        }

        return edge.getRelations().stream().anyMatch((relation) -> relation.getKind().equals(this.relation));
    }

}
