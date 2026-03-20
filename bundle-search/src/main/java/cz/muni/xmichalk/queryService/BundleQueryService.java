package cz.muni.xmichalk.queryService;

import cz.muni.xmichalk.models.QueryContext;
import cz.muni.xmichalk.models.QueryResult;
import cz.muni.xmichalk.queries.IQuery;
import cz.muni.xmichalk.storage.IStorage;
import org.openprovenance.prov.model.QualifiedName;

import java.nio.file.AccessDeniedException;

public class BundleQueryService {
    public final IStorage documentLoader;

    public BundleQueryService(IStorage documentLoader) {
        this.documentLoader = documentLoader;
    }

    public <T> QueryResult<T> evaluateBundleQuery(
            QualifiedName bundleId,
            QualifiedName startNodeId,
            IQuery<T> query,
            String authorizationHeader
    ) throws AccessDeniedException {
        QueryContext context = new QueryContext(bundleId, startNodeId, authorizationHeader, this.documentLoader);
        return query.evaluate(context);
    }
}
