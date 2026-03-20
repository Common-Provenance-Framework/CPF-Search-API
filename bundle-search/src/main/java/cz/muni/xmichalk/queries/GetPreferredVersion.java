package cz.muni.xmichalk.queries;

import cz.muni.fi.cpm.model.CpmDocument;
import cz.muni.xmichalk.bundleVersionPicker.EVersionPreference;
import cz.muni.xmichalk.bundleVersionPicker.IVersionPicker;
import cz.muni.xmichalk.bundleVersionPicker.implementations.LatestVersionPicker;
import cz.muni.xmichalk.bundleVersionPicker.implementations.SpecifiedVersionPicker;
import cz.muni.xmichalk.models.QualifiedNameData;
import cz.muni.xmichalk.models.QueryContext;
import cz.muni.xmichalk.models.QueryResult;
import cz.muni.xmichalk.storage.EBundlePart;
import cz.muni.xmichalk.storage.StorageCpmDocument;
import cz.muni.xmichalk.util.CpmUtils;
import org.openprovenance.prov.model.QualifiedName;

import java.nio.file.AccessDeniedException;

public class GetPreferredVersion implements IQuery<QualifiedNameData> {
    public EVersionPreference versionPreference;
    public String metaUri;

    public GetPreferredVersion() {
    }

    public GetPreferredVersion(EVersionPreference versionPreference) {
        this.versionPreference = versionPreference;
    }

    public GetPreferredVersion(EVersionPreference versionPreference, String metaUri) {
        this.versionPreference = versionPreference;
        this.metaUri = metaUri;
    }


    @Override public QueryResult<QualifiedNameData> evaluate(QueryContext context) throws AccessDeniedException {
        if (versionPreference == null) {
            throw new IllegalStateException(
                    "Value of versionPreference cannot be null in " + this.getClass().getName());
        }

        String metaUri = this.metaUri != null ? this.metaUri : getMetaBundleId(context).getUri();

        StorageCpmDocument retrievedDocument =
                context.documentLoader.loadMetaCpmDocument(metaUri, context.authorizationHeader);

        CpmDocument metaDocument = retrievedDocument.document;


        IVersionPicker versionPicker = null;

        switch (this.versionPreference) {
            case LATEST:
                versionPicker = new LatestVersionPicker();
                break;
            case SPECIFIED:
                versionPicker = new SpecifiedVersionPicker();
                break;
            default:
                throw new IllegalArgumentException("Unknown version preference: " + this.versionPreference);
        }

        QualifiedName pickedVersion = versionPicker.apply(context.documentId, metaDocument);

        if (pickedVersion != null) {
            return new QueryResult<>(new QualifiedNameData().from(pickedVersion), retrievedDocument.token);
        }

        return null;
    }

    private QualifiedName getMetaBundleId(QueryContext context) throws AccessDeniedException {
        StorageCpmDocument retrievedDocument = context.documentLoader.loadCpmDocument(
                context.documentId.getUri(),
                EBundlePart.TraversalInformation,
                context.authorizationHeader
        );
        CpmDocument document = retrievedDocument.document;
        return CpmUtils.getMetaBundleId(document);
    }
}
