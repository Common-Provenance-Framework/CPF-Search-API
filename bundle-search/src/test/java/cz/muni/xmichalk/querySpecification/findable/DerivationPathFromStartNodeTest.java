package cz.muni.xmichalk.querySpecification.findable;

import cz.muni.fi.cpm.model.CpmDocument;
import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.TestDocumentProvider;
import cz.muni.xmichalk.models.SubgraphWrapper;
import org.junit.jupiter.params.ParameterizedTest;
import org.openprovenance.prov.model.QualifiedName;

import java.util.List;
import java.util.stream.Stream;

import static cz.muni.xmichalk.util.NameSpaceConstants.BLANK_URI;

public class DerivationPathFromStartNodeTest {

    static Stream<Object[]> testParams() {
        return Stream.of(
                new Object[]{
                        TestDocumentProvider.samplingBundle_V1,
                        new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "StoredSampleCon_r1_Spec", null),
                        false,
                        5
                }, new Object[]{
                        TestDocumentProvider.samplingBundle_V1,
                        new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "StoredSampleCon_r1_Spec", null),
                        true,
                        3
                }, new Object[]{
                        TestDocumentProvider.samplingBundle_V1,
                        new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "StoredSampleCon_r1_Spec", null),
                        null,
                        5
                }, new Object[]{
                        TestDocumentProvider.speciesIdentificationBundle_V0,
                        new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "IdentifiedSpeciesCon", null),
                        false,
                        2
                }, new Object[]{
                        TestDocumentProvider.speciesIdentificationBundle_V0,
                        new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "IdentifiedSpeciesCon", null),
                        true,
                        5
                }, new Object[]{
                        TestDocumentProvider.speciesIdentificationBundle_V0,
                        new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "IdentifiedSpeciesCon", null),
                        null,
                        5
                }
        );
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams")
    public void testFind(CpmDocument cpmDocument, QualifiedName startNodeId, Boolean backward, int expectedNodesCount) {
        SubgraphWrapper graph = new SubgraphWrapper(cpmDocument.getNodes(), cpmDocument.getEdges());
        INode startNode = cpmDocument.getNode(startNodeId);
        DerivationPathFromStartNode derivationPathFromStartNode = new DerivationPathFromStartNode(backward);

        List<SubgraphWrapper> result = derivationPathFromStartNode.find(graph, startNode);

        assert result.size() == 1;
        assert result.getFirst().getNodes().size() == expectedNodesCount;
        assert result.getFirst().getEdges().size() == expectedNodesCount - 1;
    }
}
