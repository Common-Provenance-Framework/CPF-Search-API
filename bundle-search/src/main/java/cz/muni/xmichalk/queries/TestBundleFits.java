package cz.muni.xmichalk.queries;

import cz.muni.fi.cpm.model.CpmDocument;
import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.models.DocumentStart;
import cz.muni.xmichalk.models.QueryContext;
import cz.muni.xmichalk.models.QueryResult;
import cz.muni.xmichalk.querySpecification.ICondition;
import cz.muni.xmichalk.storage.EBundlePart;
import cz.muni.xmichalk.storage.StorageCpmDocument;

import java.nio.file.AccessDeniedException;

public class TestBundleFits implements IQuery<Boolean> {
    public ICondition<DocumentStart> condition;

    public TestBundleFits() {
    }

    public TestBundleFits(ICondition<DocumentStart> condition) {
        this.condition = condition;
    }

    @Override public QueryResult<Boolean> evaluate(QueryContext context) throws AccessDeniedException {

        if (condition == null) {
            throw new IllegalStateException("Value of condition cannot be null in " + this.getClass().getName());
        }

        StorageCpmDocument retrievedDocument = context.documentLoader.loadCpmDocument(
                context.documentId.getUri(),
                EBundlePart.Whole,
                context.authorizationHeader
        );
        CpmDocument document = retrievedDocument.document;
        INode startNode = document.getNode(context.startNodeId);

        boolean value = condition.test(new DocumentStart(document, startNode));

        return new QueryResult<>(value, retrievedDocument.token);
    }
}
