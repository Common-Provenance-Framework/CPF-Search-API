package cz.muni.xmichalk.util;

import cz.muni.fi.cpm.model.CpmDocument;
import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.TestDocumentProvider;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.openprovenance.prov.model.QualifiedName;

import java.util.stream.Stream;

import static cz.muni.xmichalk.util.NameSpaceConstants.BLANK_URI;

public class CpmUtilsTest {
    @ParameterizedTest @MethodSource("getMetaBundleIdParams") void testGetMetaBundleId(
            CpmDocument cpmDoc,
            String expectedUri
    ) {
        QualifiedName metaId = CpmUtils.getMetaBundleId(cpmDoc);

        assert metaId != null;
        assert metaId.getUri().equals(expectedUri);
    }

    static Stream<Object[]> getMetaBundleIdParams() {
        return Stream.of(
                new Object[]{
                        TestDocumentProvider.samplingBundle_V0,
                        "http://prov-storage-1:8000/api/v1/documents/meta/SamplingBundle_V0_meta"
                }, new Object[]{
                        TestDocumentProvider.processingBundle_V1,
                        "http://prov-storage-2:8000/api/v1/documents/meta/ProcessingBundle_V0_meta"
                }
        );
    }

    @ParameterizedTest @MethodSource("getGeneralConnectorIdParams")
    public void testGetGeneralConnectorId(CpmDocument cpmDoc, QualifiedName connectorId, String expectedResultIdUri) {
        INode connectorNode = cpmDoc.getNode(connectorId);

        INode referencedConnectorId = CpmUtils.getGeneralConnectorId(connectorNode);

        assert referencedConnectorId != null;
        assert referencedConnectorId.getId().getUri().equals(expectedResultIdUri);
    }

    static Stream<Object[]> getGeneralConnectorIdParams() {
        return Stream.of(
                new Object[]{
                        TestDocumentProvider.samplingBundle_V1,
                        new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "StoredSampleCon_r1_Spec", null),
                        BLANK_URI + "StoredSampleCon_r1"
                }, new Object[]{
                        TestDocumentProvider.samplingBundle_V1,
                        new org.openprovenance.prov.vanilla.QualifiedName(
                                BLANK_URI,
                                "StoredSampleCon_r2_3um_Spec",
                                null
                        ),
                        BLANK_URI + "StoredSampleCon_r2_3um"
                }, new Object[]{
                        TestDocumentProvider.samplingBundle_V1,
                        new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "ProcessedSampleConSpec", null),
                        BLANK_URI + "ProcessedSampleCon"
                }, new Object[]{
                        TestDocumentProvider.processingBundle_V1,
                        new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "ProcessedSampleConSpec", null),
                        BLANK_URI + "ProcessedSampleCon"
                }, new Object[]{
                        TestDocumentProvider.processingBundle_V1,
                        new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "StoredSampleCon_r1", null),
                        BLANK_URI + "StoredSampleCon_r1"
                }
                // backward connector
        );
    }

    @ParameterizedTest @MethodSource("chooseStartNodeParams") public void testChooseStartNode(CpmDocument cpmDoc) {
        INode chosenStartNode = CpmUtils.chooseStartNode(cpmDoc);

        assert chosenStartNode != null;
        assert cpmDoc.getNode(chosenStartNode.getId()) != null;
    }

    static Stream<Object[]> chooseStartNodeParams() {
        return Stream.of(
                new Object[]{TestDocumentProvider.samplingBundle_V0},
                new Object[]{TestDocumentProvider.samplingBundle_V1},
                new Object[]{TestDocumentProvider.processingBundle_V0},
                new Object[]{TestDocumentProvider.processingBundle_V1},
                new Object[]{TestDocumentProvider.speciesIdentificationBundle_V0},
                new Object[]{TestDocumentProvider.dnaSequencingBundle_V0},
                new Object[]{TestDocumentProvider.samplingBundle_V0_meta}
        );
    }


}
