package cz.muni.xmichalk.queries;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import cz.muni.xmichalk.models.QueryContext;
import cz.muni.xmichalk.models.QueryResult;

import java.nio.file.AccessDeniedException;


@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "type")
@JsonSubTypes(
        {
                @JsonSubTypes.Type(value = FindSubgraphsQuery.class, name = "FindSubgraphsQuery"),
                @JsonSubTypes.Type(value = TestBundleFits.class, name = "TestBundleFits"),
                @JsonSubTypes.Type(value = GetPreferredVersion.class, name = "GetPreferredVersion"),
        }
)
public interface IQuery<T> {
    QueryResult<T> evaluate(QueryContext context) throws AccessDeniedException;
}
