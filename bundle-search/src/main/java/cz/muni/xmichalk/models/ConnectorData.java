package cz.muni.xmichalk.models;

public class ConnectorData {
    public QualifiedNameData id;
    public QualifiedNameData referencedConnectorId;
    public QualifiedNameData referencedBundleId;
    public QualifiedNameData referencedMetaBundleId;
    public String referencedBundleHashValue;
    public String provenanceServiceUri;
    public String hashAlg;

    public ConnectorData() {
    }

    public ConnectorData(
            QualifiedNameData id,
            QualifiedNameData referencedConnectorId,
            QualifiedNameData referencedBundleId,
            QualifiedNameData referencedMetaBundleId,
            String referencedBundleHashValue,
            String hashAlg,
            String provenanceServiceUri
    ) {
        this.id = id;
        this.referencedConnectorId = referencedConnectorId;
        this.referencedBundleId = referencedBundleId;
        this.referencedMetaBundleId = referencedMetaBundleId;
        this.referencedBundleHashValue = referencedBundleHashValue;
        this.hashAlg = hashAlg;
        this.provenanceServiceUri = provenanceServiceUri;
    }
}
