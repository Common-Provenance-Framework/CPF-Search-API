package cz.muni.xmichalk.models;

import cz.muni.xmichalk.storage.IStorage;
import org.openprovenance.prov.model.QualifiedName;

public class QueryContext {
    public final QualifiedName documentId;
    public final QualifiedName startNodeId;
    public final String authorizationHeader;
    public final IStorage documentLoader;

    public QueryContext(
            QualifiedName documentId,
            QualifiedName startNodeId,
            String authorizationHeader,
            IStorage documentLoader
    ) {
        this.documentId = documentId;
        this.startNodeId = startNodeId;
        this.authorizationHeader = authorizationHeader;
        this.documentLoader = documentLoader;
    }
}
