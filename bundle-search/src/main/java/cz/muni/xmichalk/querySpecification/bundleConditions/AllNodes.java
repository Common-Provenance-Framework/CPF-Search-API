package cz.muni.xmichalk.querySpecification.bundleConditions;

import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.models.DocumentStart;
import cz.muni.xmichalk.querySpecification.ICondition;

public class AllNodes implements ICondition<DocumentStart> {
    public ICondition<INode> condition;

    public AllNodes() {

    }

    public AllNodes(ICondition<INode> condition) {
        this.condition = condition;
    }

    @Override public boolean test(DocumentStart target) {
        if (condition == null) {
            throw new IllegalStateException("Value of condition  " + this.getClass().getSimpleName());
        }
        return target.document.getNodes().stream().allMatch(node -> condition.test(node));
    }
}
