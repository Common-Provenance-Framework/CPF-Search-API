package cz.muni.xmichalk.util;

import com.fasterxml.jackson.databind.JsonNode;
import cz.muni.fi.cpm.merged.CpmMergedFactory;
import cz.muni.fi.cpm.model.CpmDocument;
import cz.muni.fi.cpm.model.ICpmFactory;
import cz.muni.fi.cpm.model.ICpmProvFactory;
import cz.muni.fi.cpm.vanilla.CpmProvFactory;
import cz.muni.xmichalk.TestDocumentProvider;
import org.junit.jupiter.params.ParameterizedTest;
import org.openprovenance.prov.model.Document;
import org.openprovenance.prov.model.interop.Formats;
import org.openprovenance.prov.vanilla.ProvFactory;

import java.io.IOException;
import java.util.stream.Stream;

public class ResultsTransformationUtilsTest {
    ProvFactory pF = new ProvFactory();
    ICpmFactory cF = new CpmMergedFactory(pF);
    ICpmProvFactory cPF = new CpmProvFactory(pF);


    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testDocuments")
    public void testTransformToJsonNode(CpmDocument cpmDocument) throws IOException {
        JsonNode jsonNode = ResultsTransformationUtils.transformToJsonNode(cpmDocument.toDocument());

        Document docFromJson = ProvDocumentUtils.deserialize(jsonNode.toString(), Formats.ProvFormat.JSON);
        CpmDocument newCpmDocument = new CpmDocument(docFromJson, pF, cPF, cF);

        assert (cpmDocument.getBundleId().getUri().equals(newCpmDocument.getBundleId().getUri()));
        assert (cpmDocument.getNodes().size() == newCpmDocument.getNodes().size());
        assert (cpmDocument.getEdges().size() == newCpmDocument.getEdges().size());
        assert (cpmDocument.getNodes().stream().allMatch(node -> newCpmDocument.getNode(node.getId()) != null));
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testDocuments")
    public void testEncapsulateInDocument(CpmDocument cpmDocument) {

        Document newDocument =
                ResultsTransformationUtils.encapsulateInDocument(cpmDocument.getNodes(), cpmDocument.getEdges());

        CpmDocument newCpmDocument = new CpmDocument(newDocument, pF, cPF, cF);
        assert (newCpmDocument.getNodes().size() == cpmDocument.getNodes().size());
        assert (newCpmDocument.getEdges().size() == cpmDocument.getEdges().size());
        assert (newCpmDocument.getNodes().stream().allMatch(node -> cpmDocument.getNodes(node.getId()) != null));
    }

    static Stream<Object[]> testDocuments() {
        return Stream.of(
                new Object[]{TestDocumentProvider.samplingBundle_V0},
                new Object[]{TestDocumentProvider.samplingBundle_V1},
                new Object[]{TestDocumentProvider.samplingBundle_V0_meta},
                new Object[]{TestDocumentProvider.processingBundle_V0},
                new Object[]{TestDocumentProvider.processingBundle_V1},
                new Object[]{TestDocumentProvider.processingBundle_V0_meta}
        );
    }
}
