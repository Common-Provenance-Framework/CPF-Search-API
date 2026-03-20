package cz.muni.xmichalk.models;

import org.openprovenance.prov.model.QualifiedName;

public record Connection(QualifiedName bundleId, QualifiedName connectorId) {
}
