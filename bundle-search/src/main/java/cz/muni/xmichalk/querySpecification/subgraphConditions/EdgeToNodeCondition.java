package cz.muni.xmichalk.querySpecification.subgraphConditions;

import cz.muni.fi.cpm.model.IEdge;
import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.models.EdgeToNode;
import cz.muni.xmichalk.querySpecification.ICondition;

public class EdgeToNodeCondition implements ICondition<EdgeToNode> {
    public ICondition<IEdge> edgeCondition;
    public ICondition<INode> nodeCondition;
    public Boolean nodeIsEffect;

    public EdgeToNodeCondition() {
    }

    public EdgeToNodeCondition(ICondition<IEdge> edgeCondition, ICondition<INode> nodeCondition, Boolean nodeIsEffect) {
        this.edgeCondition = edgeCondition;
        this.nodeCondition = nodeCondition;
        this.nodeIsEffect = nodeIsEffect;
    }

    public boolean test(EdgeToNode edgeToNode) {
        INode node = edgeToNode == null ? null : edgeToNode.node;
        IEdge edge = edgeToNode == null ? null : edgeToNode.edge;


        if (edgeCondition != null && edge != null && !edgeCondition.test(edge)) { // skip if edge is null (start node)
            return false;
        }

        if (nodeCondition != null && !nodeCondition.test(node)) {
            return false;
        }

        if (nodeIsEffect != null && edge != null) { // skip if edge is null (start node)
            INode effectNode = edge == null ? null : edge.getEffect();
            if (node == null || effectNode == null) {
                return false;
            }
            return nodeIsEffect.equals(effectNode.equals(node));
        }

        return true;
    }
}
