package cz.muni.xmichalk.querySpecification.nodeConditions;

import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.querySpecification.ICondition;
import cz.muni.xmichalk.util.AttributeUtils;

import java.util.List;

public class HasAttr implements ICondition<INode> {
    public String attributeNameUri;

    public HasAttr() {
    }

    public HasAttr(String attributeNameUri) {
        this.attributeNameUri = attributeNameUri;
    }

    @Override public boolean test(INode node) {
        if (attributeNameUri == null) {
            throw new IllegalStateException(
                    "Value of attributeNameUri cannot be null in " + this.getClass().getSimpleName());
        }

        Object value = AttributeUtils.getAttributeValue(node, attributeNameUri);
        return (value != null && !(value instanceof List<?> && ((List<?>) value).isEmpty()));
    }
}
