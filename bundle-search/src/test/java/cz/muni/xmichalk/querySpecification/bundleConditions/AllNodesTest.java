package cz.muni.xmichalk.querySpecification.bundleConditions;

import cz.muni.fi.cpm.model.CpmDocument;
import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.TestDocumentProvider;
import cz.muni.xmichalk.models.DocumentStart;
import org.junit.jupiter.api.Test;

public class AllNodesTest {
    @Test public void testAllNodes_allTrue() {
        CpmDocument cpmDocument = TestDocumentProvider.samplingBundle_V1;
        INode startNode = cpmDocument.getMainActivity();
        DocumentStart target = new DocumentStart(cpmDocument, startNode);

        AllNodes allNodesCondition = new AllNodes(node -> true);

        assert allNodesCondition.test(target);
    }

    @Test public void testAllNodes_allFalse() {
        CpmDocument cpmDocument = TestDocumentProvider.samplingBundle_V1;
        INode startNode = cpmDocument.getMainActivity();
        DocumentStart target = new DocumentStart(cpmDocument, startNode);

        AllNodes allNodesCondition = new AllNodes(node -> false);

        assert !allNodesCondition.test(target);
    }

    @Test public void testAllNodes_oneTrue() {
        CpmDocument cpmDocument = TestDocumentProvider.samplingBundle_V1;
        INode startNode = cpmDocument.getMainActivity();
        DocumentStart target = new DocumentStart(cpmDocument, startNode);

        AllNodes allNodesCondition = new AllNodes(node -> node == startNode);

        assert !allNodesCondition.test(target);
    }

    @Test public void testAllNodes_oneFalse() {
        CpmDocument cpmDocument = TestDocumentProvider.samplingBundle_V1;
        INode startNode = cpmDocument.getMainActivity();
        DocumentStart target = new DocumentStart(cpmDocument, startNode);

        AllNodes allNodesCondition = new AllNodes(node -> node != startNode);

        assert !allNodesCondition.test(target);
    }
}
