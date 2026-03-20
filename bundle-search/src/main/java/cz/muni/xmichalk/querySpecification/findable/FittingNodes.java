package cz.muni.xmichalk.querySpecification.findable;

import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.models.SubgraphWrapper;
import cz.muni.xmichalk.querySpecification.ICondition;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class FittingNodes implements IFindableSubgraph {
    public ICondition<INode> nodeCondition;
    public IFindableSubgraph startsIn = new WholeGraph();

    public FittingNodes() {
    }

    public FittingNodes(ICondition<INode> nodeCondition) {
        this.nodeCondition = nodeCondition;
    }

    public FittingNodes(ICondition<INode> nodeCondition, IFindableSubgraph startsIn) {
        this.nodeCondition = nodeCondition;
        this.startsIn = startsIn;
    }

    @Override public List<SubgraphWrapper> find(SubgraphWrapper graph, INode startNode) {
        if (nodeCondition == null) {
            throw new IllegalStateException(
                    "Value of nodeCondition cannot be null in " + this.getClass().getSimpleName());
        }
        if (startsIn == null) {
            throw new IllegalStateException("Value of startsIn cannot be null in " + this.getClass().getSimpleName());
        }

        Set<INode> startingNodes =
                startsIn.find(graph, startNode).stream().flatMap(subgraph -> subgraph.getNodes().stream())
                        .collect(Collectors.toSet());

        return startingNodes.stream().filter(node -> nodeCondition.test(node))
                .map(node -> new SubgraphWrapper(List.of(node), new ArrayList<>())).toList();
    }
}
