package cz.muni.xmichalk.queries;

import cz.muni.fi.cpm.model.CpmDocument;
import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.MockedStorage;
import cz.muni.xmichalk.TestDocumentProvider;
import cz.muni.xmichalk.models.QueryContext;
import cz.muni.xmichalk.models.SubgraphWrapper;
import cz.muni.xmichalk.querySpecification.findable.IFindableSubgraph;
import org.junit.jupiter.params.ParameterizedTest;

import java.nio.file.AccessDeniedException;
import java.util.List;
import java.util.stream.Stream;

public class GetNodeIdsTest {
    static Stream<Object[]> testParams() {
        return Stream.of(
                new Object[]{
                        TestDocumentProvider.samplingBundle_V0,
                        TestDocumentProvider.samplingBundle_V0.getForwardConnectors().getFirst()
                }, new Object[]{
                        TestDocumentProvider.samplingBundle_V1,
                        TestDocumentProvider.samplingBundle_V1.getForwardConnectors().getFirst()
                }, new Object[]{
                        TestDocumentProvider.processingBundle_V0,
                        TestDocumentProvider.processingBundle_V0.getForwardConnectors().getFirst()
                }, new Object[]{
                        TestDocumentProvider.processingBundle_V1,
                        TestDocumentProvider.processingBundle_V1.getForwardConnectors().getFirst()
                }
        );
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams")
    public void testGetNodeIds_unfiltered(CpmDocument cpmDocument, INode startNode) throws AccessDeniedException {
        GetNodeIds getNodeIdsQuery = new GetNodeIds((g, n) -> List.of(g));
        QueryContext context =
                new QueryContext(cpmDocument.getBundleId(), startNode.getId(), null, new MockedStorage());

        var result = getNodeIdsQuery.evaluate(context).result;

        assert result.size() == cpmDocument.getNodes().size();
        assert cpmDocument.getNodes().stream().allMatch(node -> result.stream()
                .anyMatch(nodeId -> nodeId.toQN().getUri().equals(node.getId().getUri())));
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams")
    public void testGetNodeIds_filteredTo1(CpmDocument cpmDocument, INode startNode) throws AccessDeniedException {
        INode mainActivityNode = cpmDocument.getMainActivity();

        IFindableSubgraph fromSubgraph = (g, n) -> List.of(new SubgraphWrapper(List.of(mainActivityNode), List.of()));

        GetNodeIds getNodeIdsQuery = new GetNodeIds(fromSubgraph);
        QueryContext context =
                new QueryContext(cpmDocument.getBundleId(), startNode.getId(), null, new MockedStorage());

        var result = getNodeIdsQuery.evaluate(context).result;

        assert result.size() == 1;
        assert result.getFirst().toQN().getUri().equals(mainActivityNode.getId().getUri());
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams")
    public void testGetNodeIds_filteredToNone(CpmDocument cpmDocument, INode startNode) throws AccessDeniedException {
        GetNodeIds getNodeIdsQuery = new GetNodeIds((g, n) -> List.of());
        QueryContext context =
                new QueryContext(cpmDocument.getBundleId(), startNode.getId(), null, new MockedStorage());

        var result = getNodeIdsQuery.evaluate(context).result;

        assert result.isEmpty();
    }

}
