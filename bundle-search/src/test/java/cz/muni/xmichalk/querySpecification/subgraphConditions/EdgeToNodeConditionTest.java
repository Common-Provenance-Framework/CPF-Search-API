package cz.muni.xmichalk.querySpecification.subgraphConditions;

import cz.muni.fi.cpm.merged.MergedEdge;
import cz.muni.fi.cpm.merged.MergedNode;
import cz.muni.fi.cpm.model.IEdge;
import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.models.EdgeToNode;
import cz.muni.xmichalk.models.QualifiedNameData;
import org.junit.jupiter.api.Test;
import org.openprovenance.prov.model.StatementOrBundle;

import java.util.ArrayList;

import static cz.muni.xmichalk.util.NameSpaceConstants.BLANK_URI;

public class EdgeToNodeConditionTest {
    private static final INode genericEntityNode =
            new MergedNode(new org.openprovenance.prov.vanilla.Entity(
                    new QualifiedNameData(
                            BLANK_URI,
                                                                                            "entity1"
            ).toQN(), new ArrayList<>()
            ));

    private static final INode specificEntityNode =
            new MergedNode(new org.openprovenance.prov.vanilla.Entity(
                    new QualifiedNameData(
                            BLANK_URI,
                                                                                            "entity2"
            ).toQN(), new ArrayList<>()
            ));

    private static final IEdge specializationEdge =
            new MergedEdge(() -> StatementOrBundle.Kind.PROV_SPECIALIZATION, specificEntityNode, genericEntityNode);

    @Test public void testEdgeToNodeCondition_allTrue() {
        EdgeToNode edgeToNode = new EdgeToNode(specializationEdge, specificEntityNode);

        EdgeToNodeCondition condition = new EdgeToNodeCondition(edge -> true, node -> true, null);

        assert condition.test(edgeToNode);
    }

    @Test public void testEdgeToNodeCondition_edgeFalse() {
        EdgeToNode edgeToNode = new EdgeToNode(specializationEdge, specificEntityNode);

        EdgeToNodeCondition condition = new EdgeToNodeCondition(edge -> false, node -> true, null);

        assert !condition.test(edgeToNode);
    }

    @Test public void testEdgeToNodeCondition_nodeFalse() {
        EdgeToNode edgeToNode = new EdgeToNode(specializationEdge, specificEntityNode);

        EdgeToNodeCondition condition = new EdgeToNodeCondition(edge -> false, node -> true, null);

        assert !condition.test(edgeToNode);
    }

    @Test public void testEdgeToNodeCondition_isEffectTrue() {
        EdgeToNode edgeToNode = new EdgeToNode(specializationEdge, specificEntityNode);

        EdgeToNodeCondition condition = new EdgeToNodeCondition(edge -> true, node -> true, true);

        assert condition.test(edgeToNode);
    }

    @Test public void testEdgeToNodeCondition_isEffectFalse() {
        EdgeToNode edgeToNode = new EdgeToNode(specializationEdge, genericEntityNode);

        EdgeToNodeCondition condition = new EdgeToNodeCondition(edge -> true, node -> true, true);

        assert !condition.test(edgeToNode);
    }

    @Test public void testEdgeToNodeCondition_isNotEffectTrue() {
        EdgeToNode edgeToNode = new EdgeToNode(specializationEdge, genericEntityNode);

        EdgeToNodeCondition condition = new EdgeToNodeCondition(edge -> true, node -> true, false);

        assert condition.test(edgeToNode);
    }

    @Test public void testEdgeToNodeCondition_isNotEffectFalse() {
        EdgeToNode edgeToNode = new EdgeToNode(specializationEdge, specificEntityNode);

        EdgeToNodeCondition condition = new EdgeToNodeCondition(edge -> true, node -> true, false);

        assert !condition.test(edgeToNode);
    }

    @Test public void testEdgeToNodeCondition_nullEdgeSkipped() {
        EdgeToNode edgeToNode = new EdgeToNode(null, genericEntityNode);

        EdgeToNodeCondition condition = new EdgeToNodeCondition(edge -> false, node -> true, true);

        assert condition.test(edgeToNode);
    }
}
