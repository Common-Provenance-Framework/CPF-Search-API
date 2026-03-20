package cz.muni.xmichalk.models;

import org.openprovenance.prov.model.QualifiedName;

public class QualifiedNameData {
    public String nameSpaceUri;
    public String localPart;

    public QualifiedNameData() {
    }

    public QualifiedNameData(String nameSpaceUri, String localPart) {
        this.nameSpaceUri = nameSpaceUri;
        this.localPart = localPart;
    }


    public QualifiedNameData from(QualifiedName qn) {
        if (qn == null) {
            return null;
        }

        this.nameSpaceUri = qn.getNamespaceURI();
        this.localPart = qn.getLocalPart();

        return this;
    }

    public QualifiedName toQN() {
        return new org.openprovenance.prov.vanilla.QualifiedName(this.nameSpaceUri, this.localPart, null);
    }

    @Override public String toString() {
        return nameSpaceUri + localPart;
    }
}
