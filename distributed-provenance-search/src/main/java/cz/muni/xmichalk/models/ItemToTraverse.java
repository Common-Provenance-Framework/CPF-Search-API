package cz.muni.xmichalk.models;

import cz.muni.xmichalk.validity.EValidityCheck;
import org.openprovenance.prov.model.QualifiedName;

import java.util.List;
import java.util.Map;

public class ItemToTraverse {
    public QualifiedName bundleId;
    public QualifiedName connectorId;
    public QualifiedName metaBundleId;
    public String provServiceUri;
    public boolean pathIntegrity;
    public List<Map.Entry<EValidityCheck, Boolean>> pathValidityChecks;

    public ItemToTraverse(
            QualifiedName bundleId,
            QualifiedName connectorId,
            QualifiedName metaBundleId,
            String provServiceUri,
            boolean pathIntegrity,
            List<Map.Entry<EValidityCheck, Boolean>> pathValidityChecks
    ) {
        this.bundleId = bundleId;
        this.connectorId = connectorId;
        this.metaBundleId = metaBundleId;
        this.provServiceUri = provServiceUri;
        this.pathIntegrity = pathIntegrity;
        this.pathValidityChecks = pathValidityChecks;
    }

}
