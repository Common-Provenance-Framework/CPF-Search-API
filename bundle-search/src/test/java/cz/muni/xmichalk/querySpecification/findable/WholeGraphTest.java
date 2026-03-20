package cz.muni.xmichalk.querySpecification.findable;

import cz.muni.fi.cpm.model.CpmDocument;
import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.TestDocumentProvider;
import cz.muni.xmichalk.models.SubgraphWrapper;
import org.junit.jupiter.params.ParameterizedTest;

import java.util.List;
import java.util.stream.Stream;

import static cz.muni.xmichalk.util.NameSpaceConstants.BLANK_URI;

public class WholeGraphTest {
    static Stream<Object[]> testParams() {
        return Stream.of(
                new Object[]{
                        TestDocumentProvider.samplingBundle_V1,
                        new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "StoredSampleCon_r1_Spec", null)
                }, new Object[]{
                        TestDocumentProvider.samplingBundle_V1,
                        new org.openprovenance.prov.vanilla.QualifiedName(
                                BLANK_URI,
                                "StoredSampleCon_r2_3um_Spec",
                                null
                        )
                }, new Object[]{
                        TestDocumentProvider.processingBundle_V1,
                        new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "ProcessedSampleConSpec", null)
                }, new Object[]{
                        TestDocumentProvider.processingBundle_V1,
                        new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "StoredSampleCon_r1", null)
                }
        );
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams")
    public void testFind(CpmDocument cpmDocument, org.openprovenance.prov.model.QualifiedName startNodeId) {
        INode startNode = cpmDocument.getNode(startNodeId);
        SubgraphWrapper subgraphWrapper = new SubgraphWrapper(cpmDocument.getNodes(), cpmDocument.getEdges());
        WholeGraph wholeGraph = new WholeGraph();

        List<SubgraphWrapper> results = wholeGraph.find(subgraphWrapper, startNode);

        assert results.size() == 1;
        assert results.getFirst().getNodes().size() == cpmDocument.getNodes().size();
        assert results.getFirst().getEdges().size() == cpmDocument.getEdges().size();

    }
}
