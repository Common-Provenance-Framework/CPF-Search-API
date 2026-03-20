package cz.muni.xmichalk.queries;

import cz.muni.fi.cpm.model.CpmDocument;
import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.MockedStorage;
import cz.muni.xmichalk.TestDocumentProvider;
import cz.muni.xmichalk.models.ConnectorData;
import cz.muni.xmichalk.models.QueryContext;
import org.junit.jupiter.params.ParameterizedTest;

import java.nio.file.AccessDeniedException;
import java.util.List;
import java.util.stream.Stream;

public class GetConnectorsTest {

    static Stream<Object[]> testParams() {
        return Stream.of(
                new Object[]{
                        TestDocumentProvider.samplingBundle_V0,
                        TestDocumentProvider.samplingBundle_V0.getForwardConnectors().getFirst(),
                        0,
                        2
                }, new Object[]{
                        TestDocumentProvider.samplingBundle_V1,
                        TestDocumentProvider.samplingBundle_V1.getForwardConnectors().getFirst(),
                        0,
                        6
                }, new Object[]{
                        TestDocumentProvider.processingBundle_V0,
                        TestDocumentProvider.processingBundle_V0.getForwardConnectors().getFirst(),
                        1,
                        1
                }, new Object[]{
                        TestDocumentProvider.processingBundle_V1,
                        TestDocumentProvider.processingBundle_V1.getForwardConnectors().getFirst(),
                        1,
                        2
                }
        );
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams")
    public void testGetConnectors_backward_unfiltered(
            CpmDocument cpmDocument,
            INode startNode,
            int backwardConnectors,
            int forwardConnectors
    ) throws AccessDeniedException {
        GetConnectors getAllConnectorsQuery = new GetConnectors(true, (g, n) -> List.of(g));
        QueryContext context =
                new QueryContext(cpmDocument.getBundleId(), startNode.getId(), null, new MockedStorage());

        List<ConnectorData> result = getAllConnectorsQuery.evaluate(context).result;

        assert result.size() == backwardConnectors;
        assert cpmDocument.getBackwardConnectors().stream().allMatch(connectorNode -> result.stream()
                .anyMatch(connectorData -> connectorData.id.toQN().getUri().equals(connectorNode.getId().getUri())));
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams")
    public void testGetConnectors_forward_unfiltered(
            CpmDocument cpmDocument,
            INode startNode,
            int backwardConnectors,
            int forwardConnectors
    ) throws AccessDeniedException {
        GetConnectors getAllConnectorsQuery = new GetConnectors(false, (g, n) -> List.of(g));
        QueryContext context =
                new QueryContext(cpmDocument.getBundleId(), startNode.getId(), null, new MockedStorage());

        List<ConnectorData> result = getAllConnectorsQuery.evaluate(context).result;

        assert result.size() == forwardConnectors;
        assert cpmDocument.getForwardConnectors().stream().allMatch(connectorNode -> result.stream()
                .anyMatch(connectorData -> connectorData.id.toQN().getUri().equals(connectorNode.getId().getUri())));
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams")
    public void testGetConnectors_all_unfiltered(
            CpmDocument cpmDocument,
            INode startNode,
            int backwardConnectors,
            int forwardConnectors
    ) throws AccessDeniedException {
        GetConnectors getAllConnectorsQuery = new GetConnectors(null, (g, n) -> List.of(g));
        QueryContext context =
                new QueryContext(cpmDocument.getBundleId(), startNode.getId(), null, new MockedStorage());

        List<ConnectorData> result = getAllConnectorsQuery.evaluate(context).result;

        assert result.size() == backwardConnectors + forwardConnectors;
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams")
    public void testGetConnectors_all_filteredToNothing(
            CpmDocument cpmDocument,
            INode startNode,
            int backwardConnectors,
            int forwardConnectors
    ) throws AccessDeniedException {
        GetConnectors getAllConnectorsQuery = new GetConnectors(null, (g, n) -> List.of());
        QueryContext context =
                new QueryContext(cpmDocument.getBundleId(), startNode.getId(), null, new MockedStorage());

        List<ConnectorData> result = getAllConnectorsQuery.evaluate(context).result;

        assert result.isEmpty();
    }
}
