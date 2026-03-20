package cz.muni.xmichalk.queries;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import cz.muni.fi.cpm.model.CpmDocument;
import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.models.QueryContext;
import cz.muni.xmichalk.models.QueryResult;
import cz.muni.xmichalk.models.SubgraphWrapper;
import cz.muni.xmichalk.querySpecification.findable.IFindableSubgraph;
import cz.muni.xmichalk.querySpecification.findable.WholeGraph;
import cz.muni.xmichalk.storage.EBundlePart;
import cz.muni.xmichalk.storage.StorageCpmDocument;

import java.nio.file.AccessDeniedException;
import java.util.List;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "type")
@JsonSubTypes(
        {
                @JsonSubTypes.Type(value = GetConnectors.class, name = "GetConnectors"),
                @JsonSubTypes.Type(value = GetNodeIds.class, name = "GetNodeIds"),
                @JsonSubTypes.Type(value = GetNodes.class, name = "GetNodes"),
                @JsonSubTypes.Type(value = GetSubgraphs.class, name = "GetSubgraphs"),
        }
)
public abstract class FindSubgraphsQuery<T> implements IQuery<T> {
    public IFindableSubgraph fromSubgraphs = new WholeGraph();

    protected QueryResult<T> evaluate(QueryContext context, IFindableSubgraph fromSubgraphs)
            throws AccessDeniedException {
        if (fromSubgraphs == null) {
            throw new IllegalStateException("Value of fromSubgraphs cannot be null in " + this.getClass().getName());
        }

        EBundlePart requiredBundlePart = decideRequiredBundlePart();
        StorageCpmDocument retrievedDocument = context.documentLoader.loadCpmDocument(
                context.documentId.getUri(),
                requiredBundlePart,
                context.authorizationHeader
        );
        CpmDocument document = retrievedDocument.document;
        INode startNode = document.getNode(context.startNodeId);

        List<SubgraphWrapper> subgraphs = fromSubgraphs.find(new SubgraphWrapper(document), startNode);

        return new QueryResult<T>(transformResult(subgraphs), retrievedDocument.token);
    }

    @Override public QueryResult<T> evaluate(QueryContext context) throws AccessDeniedException {
        return evaluate(context, fromSubgraphs);
    }

    protected abstract EBundlePart decideRequiredBundlePart();

    protected abstract T transformResult(List<SubgraphWrapper> subgraphs);
}
