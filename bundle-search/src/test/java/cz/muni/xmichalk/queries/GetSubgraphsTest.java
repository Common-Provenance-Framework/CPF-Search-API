package cz.muni.xmichalk.queries;

import cz.muni.fi.cpm.merged.CpmMergedFactory;
import cz.muni.fi.cpm.model.CpmDocument;
import cz.muni.fi.cpm.model.ICpmFactory;
import cz.muni.fi.cpm.model.ICpmProvFactory;
import cz.muni.fi.cpm.model.INode;
import cz.muni.fi.cpm.vanilla.CpmProvFactory;
import cz.muni.xmichalk.MockedStorage;
import cz.muni.xmichalk.TestDocumentProvider;
import cz.muni.xmichalk.models.QueryContext;
import cz.muni.xmichalk.models.SubgraphWrapper;
import cz.muni.xmichalk.util.ProvDocumentUtils;
import org.junit.jupiter.params.ParameterizedTest;
import org.openprovenance.prov.model.Document;
import org.openprovenance.prov.model.interop.Formats;
import org.openprovenance.prov.vanilla.ProvFactory;

import java.io.IOException;
import java.util.List;
import java.util.stream.Stream;

public class GetSubgraphsTest {
    ProvFactory pF = new ProvFactory();
    ICpmFactory cF = new CpmMergedFactory(pF);
    ICpmProvFactory cPF = new CpmProvFactory(pF);

    static Stream<Object[]> testParams() {
        return Stream.of(
                new Object[]{
                        TestDocumentProvider.samplingBundle_V1,
                        TestDocumentProvider.samplingBundle_V1.getForwardConnectors().getFirst()
                }, new Object[]{
                        TestDocumentProvider.processingBundle_V1,
                        TestDocumentProvider.processingBundle_V1.getForwardConnectors().getFirst()
                }
        );
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams")
    public void testSubgraphs_wholeGraph(CpmDocument cpmDocument, INode startNode) throws IOException {
        GetSubgraphs getSubgraphsQuery = new GetSubgraphs((g, n) -> List.of(g));
        QueryContext context =
                new QueryContext(cpmDocument.getBundleId(), startNode.getId(), null, new MockedStorage());


        var result = getSubgraphsQuery.evaluate(context).result;

        assert result != null;
        assert result.size() == 1;
        Document resultDocument = ProvDocumentUtils.deserialize(result.getFirst().toString(), Formats.ProvFormat.JSON);
        CpmDocument resultCpmDocument = new CpmDocument(resultDocument, pF, cPF, cF);
        assert resultCpmDocument.getNodes().size() == cpmDocument.getNodes().size();
        assert resultCpmDocument.getEdges().size() == cpmDocument.getEdges().size();
        assert cpmDocument.getNodes().stream().allMatch(node -> resultCpmDocument.getNodes().stream()
                .anyMatch(resultNode -> resultNode.getId().getUri().equals(node.getId().getUri())));
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams")
    public void testGetSubgraphs_multiple(CpmDocument cpmDocument, INode startNode) throws IOException {
        INode mainActivityNode = cpmDocument.getMainActivity();
        GetSubgraphs getSubgraphsQuery = new GetSubgraphs((g, n) -> List.of(
                new SubgraphWrapper(List.of(mainActivityNode), List.of()),
                new SubgraphWrapper(cpmDocument.getNodes(), cpmDocument.getEdges())
        ));
        QueryContext context =
                new QueryContext(cpmDocument.getBundleId(), startNode.getId(), null, new MockedStorage());

        var result = getSubgraphsQuery.evaluate(context).result;

        assert result.size() == 2;
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams")
    public void testGetSubgraphs_none(CpmDocument cpmDocument, INode startNode) throws IOException {
        GetSubgraphs getSubgraphsQuery = new GetSubgraphs((g, n) -> List.of());
        QueryContext context =
                new QueryContext(cpmDocument.getBundleId(), startNode.getId(), null, new MockedStorage());

        var result = getSubgraphsQuery.evaluate(context).result;

        assert result.isEmpty();
    }
}
