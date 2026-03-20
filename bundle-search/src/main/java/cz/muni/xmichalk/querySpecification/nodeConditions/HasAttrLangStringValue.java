package cz.muni.xmichalk.querySpecification.nodeConditions;

import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.querySpecification.ICondition;
import cz.muni.xmichalk.util.AttributeUtils;
import org.openprovenance.prov.model.LangString;

public class HasAttrLangStringValue implements ICondition<INode> {
    public String attributeNameUri;
    public String langRegex;
    public String valueRegex;

    public HasAttrLangStringValue() {
    }

    public HasAttrLangStringValue(String attributeNameUri, String langRegex, String valueRegex) {
        this.attributeNameUri = attributeNameUri;
        this.langRegex = langRegex;
        this.valueRegex = valueRegex;
    }

    @Override public boolean test(INode node) {
        if (attributeNameUri == null) {
            throw new IllegalStateException(
                    "Value of attributeNameUri cannot be null in " + this.getClass().getSimpleName());
        }
        if (langRegex == null && valueRegex == null) {
            throw new IllegalStateException(
                    "At least one of langRegex or valueRegex must be non-null in " + this.getClass().getSimpleName());
        }

        try {
            return AttributeUtils.hasAttributeTargetValue(
                    node, attributeNameUri, LangString.class, (langString) -> {
                        boolean langMatch = langRegex == null || langString.getLang().matches(langRegex);
                        boolean valueMatch = valueRegex == null || langString.getValue().matches(valueRegex);
                        return langMatch && valueMatch;
                    }
            );
        } catch (Exception e) {
            return false;
        }
    }

}
