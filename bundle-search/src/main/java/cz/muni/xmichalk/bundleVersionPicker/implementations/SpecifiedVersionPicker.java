package cz.muni.xmichalk.bundleVersionPicker.implementations;

import cz.muni.fi.cpm.model.CpmDocument;
import cz.muni.xmichalk.bundleVersionPicker.IVersionPicker;
import org.openprovenance.prov.model.QualifiedName;

public class SpecifiedVersionPicker implements IVersionPicker {

    @Override public QualifiedName apply(final QualifiedName bundleId, final CpmDocument metaDocument) {
        return bundleId;
    }
}
