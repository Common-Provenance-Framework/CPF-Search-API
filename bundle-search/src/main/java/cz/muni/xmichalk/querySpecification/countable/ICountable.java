package cz.muni.xmichalk.querySpecification.countable;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import cz.muni.xmichalk.querySpecification.findable.*;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "type")
@JsonSubTypes(
        {
                @JsonSubTypes.Type(value = CountConstant.class, name = "CountConstant"),

                @JsonSubTypes.Type(value = FittingNodes.class, name = "FittingNodes"),
                @JsonSubTypes.Type(value = FittingLinearSubgraphs.class, name = "FittingLinearSubgraphs"),
                @JsonSubTypes.Type(value = FilteredSubgraphs.class, name = "FilteredSubgraphs"),
                @JsonSubTypes.Type(value = StartNode.class, name = "StartNode"),
                @JsonSubTypes.Type(value = WholeGraph.class, name = "WholeGraph"),
                @JsonSubTypes.Type(value = DerivationPathFromStartNode.class, name = "DerivationPathFromStartNode"),

        }
)
public interface ICountable<T> {
    int count(T source);

}
