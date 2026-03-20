package cz.muni.xmichalk.dto;

public class ConnectorDTO {
    public QualifiedNameDTO id;
    public QualifiedNameDTO referencedConnectorId;
    public QualifiedNameDTO referencedBundleId;
    public QualifiedNameDTO referencedMetaBundleId;
    public String referencedBundleHashValue;
    public String hashAlg;
    public String provenanceServiceUri;

    public ConnectorDTO() {
    }

    public ConnectorDTO(
            QualifiedNameDTO id,
            QualifiedNameDTO referencedConnectorId,
            QualifiedNameDTO referencedBundleId,
            QualifiedNameDTO referencedMetaBundleId,
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
