package cz.muni.xmichalk.bundleVersionPicker;

import cz.muni.fi.cpm.model.CpmDocument;
import cz.muni.xmichalk.TestDocumentProvider;
import cz.muni.xmichalk.bundleVersionPicker.implementations.SpecifiedVersionPicker;
import org.junit.jupiter.params.ParameterizedTest;
import org.openprovenance.prov.model.QualifiedName;

import java.util.stream.Stream;

public class SpecifiedVersionPickerTest {


    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("params")
    public void testApply(CpmDocument cpmDoc) {

        QualifiedName bundleId = new SpecifiedVersionPicker().apply(cpmDoc.getBundleId(), null);

        assert bundleId.getUri().equals(cpmDoc.getBundleId().getUri());
    }

    static Stream<Object[]> params() {
        return Stream.of(
                new Object[]{TestDocumentProvider.samplingBundle_V0},
                new Object[]{TestDocumentProvider.samplingBundle_V1},
                new Object[]{TestDocumentProvider.processingBundle_V0},
                new Object[]{TestDocumentProvider.processingBundle_V1},
                new Object[]{TestDocumentProvider.speciesIdentificationBundle_V0},
                new Object[]{TestDocumentProvider.dnaSequencingBundle_V0}
        );
    }
}