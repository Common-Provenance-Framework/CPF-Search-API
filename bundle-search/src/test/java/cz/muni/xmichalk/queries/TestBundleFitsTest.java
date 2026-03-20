package cz.muni.xmichalk.queries;

import cz.muni.fi.cpm.model.CpmDocument;
import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.MockedStorage;
import cz.muni.xmichalk.TestDocumentProvider;
import cz.muni.xmichalk.models.QueryContext;
import org.junit.jupiter.params.ParameterizedTest;

import java.nio.file.AccessDeniedException;
import java.util.stream.Stream;

public class TestBundleFitsTest {
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
    public void testBundleFits_true(CpmDocument cpmDocument, INode startNode) throws AccessDeniedException {
        TestBundleFits testBundleFits =
                new TestBundleFits((bundleStart) -> bundleStart.startNode.getId().equals(startNode.getId()));
        QueryContext context =
                new QueryContext(cpmDocument.getBundleId(), startNode.getId(), null, new MockedStorage());

        assert testBundleFits.evaluate(context).result;
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams")
    public void testBundleFits_false(CpmDocument cpmDocument, INode startNode) throws AccessDeniedException {
        TestBundleFits testBundleFits = new TestBundleFits((bundleStart) -> false);
        QueryContext context =
                new QueryContext(cpmDocument.getBundleId(), startNode.getId(), null, new MockedStorage());

        assert !testBundleFits.evaluate(context).result;
    }
}
