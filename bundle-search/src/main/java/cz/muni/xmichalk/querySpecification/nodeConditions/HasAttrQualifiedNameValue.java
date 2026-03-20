package cz.muni.xmichalk.querySpecification.nodeConditions;

import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.querySpecification.ICondition;
import cz.muni.xmichalk.util.AttributeUtils;
import org.openprovenance.prov.model.QualifiedName;

public class HasAttrQualifiedNameValue implements ICondition<INode> {
    public String attributeNameUri;
    public String valueUriRegex;

    public HasAttrQualifiedNameValue() {
    }

    public HasAttrQualifiedNameValue(String attributeNameUri, String regex) {
        this.attributeNameUri = attributeNameUri;
        this.valueUriRegex = regex;
    }

    @Override public boolean test(INode node) {
        if (attributeNameUri == null) {
            throw new IllegalStateException(
                    "Value of attributeNameUri cannot be null in " + this.getClass().getSimpleName());
        }
        if (valueUriRegex == null) {
            throw new IllegalStateException("Value of uriRegex cannot be null in " + this.getClass().getSimpleName());
        }

        try {
            return AttributeUtils.hasAttributeTargetValue(
                    node,
                    attributeNameUri,
                    QualifiedName.class,
                    (qn) -> qn.getUri().matches(valueUriRegex)
            );
        } catch (Exception e) {
            return false;
        }
    }
}
