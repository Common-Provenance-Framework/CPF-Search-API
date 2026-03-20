package cz.muni.xmichalk.querySpecification.nodeConditions;

import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.querySpecification.ICondition;
import org.openprovenance.prov.model.StatementOrBundle;

public class IsKind implements ICondition<INode> {
    public StatementOrBundle.Kind kind;

    public IsKind() {
    }

    public IsKind(StatementOrBundle.Kind kind) {
        this.kind = kind;
    }

    @Override public boolean test(INode node) {
        if (kind == null) {
            throw new IllegalStateException("Value of kind cannot be null in " + this.getClass().getSimpleName());
        }
        return node.getKind().equals(kind);
    }
}
