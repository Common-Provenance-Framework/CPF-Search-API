package cz.muni.xmichalk.bundleVersionPicker;

import cz.muni.fi.cpm.model.CpmDocument;
import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.TestDocumentProvider;
import cz.muni.xmichalk.bundleVersionPicker.implementations.LatestVersionPicker;
import org.junit.jupiter.api.Test;
import org.openprovenance.prov.model.QualifiedName;

public class LatestVersionPickerTest {
    @Test public void testPickLatestVersionNode() {
        CpmDocument metaCpmDoc = TestDocumentProvider.samplingBundle_V0_meta;

        INode latestVersionNode = LatestVersionPicker.pickLatestVersionNode(metaCpmDoc);

        assert latestVersionNode != null;
        assert latestVersionNode.getId().getUri().equals(TestDocumentProvider.samplingBundle_V1.getBundleId().getUri());
    }

    @Test public void testApply() {
        LatestVersionPicker picker = new LatestVersionPicker();

        QualifiedName latestBundleVersion = picker.apply(
                TestDocumentProvider.samplingBundle_V0.getBundleId(),
                TestDocumentProvider.samplingBundle_V0_meta
        );

        assert latestBundleVersion != null;
        assert latestBundleVersion.getUri().equals(TestDocumentProvider.samplingBundle_V1.getBundleId().getUri());

    }
}
