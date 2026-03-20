package cz.muni.xmichalk.querySpecification.nodeConditions;

import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.querySpecification.ICondition;

public class HasId implements ICondition<INode> {
    public String idUriRegex;

    public HasId() {
    }

    public HasId(String idUriRegex) {
        this.idUriRegex = idUriRegex;
    }

    @Override public boolean test(INode node) {
        if (idUriRegex == null) {
            throw new IllegalStateException(
                    "Value of attributeNameUri cannot be null in " + this.getClass().getSimpleName());
        }

        return node.getId().getUri().matches(idUriRegex);
    }
}
