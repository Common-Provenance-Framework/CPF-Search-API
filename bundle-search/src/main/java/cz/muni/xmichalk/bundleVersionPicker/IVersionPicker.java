package cz.muni.xmichalk.bundleVersionPicker;

import cz.muni.fi.cpm.model.CpmDocument;
import org.openprovenance.prov.model.QualifiedName;

public interface IVersionPicker {
    QualifiedName apply(QualifiedName bundleId, CpmDocument metaDocument);
}
