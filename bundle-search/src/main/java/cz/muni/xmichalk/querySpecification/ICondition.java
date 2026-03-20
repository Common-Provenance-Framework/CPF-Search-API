package cz.muni.xmichalk.querySpecification;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import cz.muni.xmichalk.querySpecification.bundleConditions.AllNodes;
import cz.muni.xmichalk.querySpecification.countable.CountComparisonCondition;
import cz.muni.xmichalk.querySpecification.logicalOperations.*;
import cz.muni.xmichalk.querySpecification.nodeConditions.*;
import cz.muni.xmichalk.querySpecification.subgraphConditions.DerivationPathCondition;
import cz.muni.xmichalk.querySpecification.subgraphConditions.EdgeToNodeCondition;
import cz.muni.xmichalk.querySpecification.subgraphConditions.edgeConditions.IsRelation;

import java.util.function.Predicate;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "type")
@JsonSubTypes(
        {
                @JsonSubTypes.Type(value = HasAttr.class, name = "HasAttr"),
                @JsonSubTypes.Type(value = HasAttrLangStringValue.class, name = "HasAttrLangStringValue"),
                @JsonSubTypes.Type(value = HasAttrQualifiedNameValue.class, name = "HasAttrQualifiedNameValue"),
                @JsonSubTypes.Type(value = HasAttrTimestampValue.class, name = "HasAttrTimestampValue"),
                @JsonSubTypes.Type(value = HasId.class, name = "HasId"),
                @JsonSubTypes.Type(value = IsKind.class, name = "IsKind"),

                @JsonSubTypes.Type(value = IsRelation.class, name = "IsRelation"),
                @JsonSubTypes.Type(value = EdgeToNodeCondition.class, name = "EdgeToNodeCondition"),
                @JsonSubTypes.Type(value = DerivationPathCondition.class, name = "DerivationPathCondition"),

                @JsonSubTypes.Type(value = CountComparisonCondition.class, name = "CountComparisonCondition"),
                @JsonSubTypes.Type(value = AllNodes.class, name = "AllNodes"),

                @JsonSubTypes.Type(value = AllTrue.class, name = "AllTrue"),
                @JsonSubTypes.Type(value = AnyTrue.class, name = "AnyTrue"),
                @JsonSubTypes.Type(value = Either.class, name = "Either"),
                @JsonSubTypes.Type(value = Implication.class, name = "Implication"),
                @JsonSubTypes.Type(value = Negation.class, name = "Negation"),
        }
)
public interface ICondition<T> extends Predicate<T> {
    @Override boolean test(T target);
}
