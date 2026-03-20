package cz.muni.xmichalk.dto;

import org.openprovenance.prov.model.QualifiedName;

public class QualifiedNameDTO {
    public String nameSpaceUri;
    public String localPart;

    public QualifiedNameDTO() {
    }

    public QualifiedNameDTO(String nameSpaceUri, String localPart) {
        this.nameSpaceUri = nameSpaceUri;
        this.localPart = localPart;
    }

    public QualifiedName toQN() {
        return new org.openprovenance.prov.vanilla.QualifiedName(this.nameSpaceUri, this.localPart, null);
    }

    public QualifiedNameDTO from(QualifiedName qn) {
        if (qn == null) {
            return null;
        }
        this.nameSpaceUri = qn.getNamespaceURI();
        this.localPart = qn.getLocalPart();
        return this;
    }
}
