package cz.muni.xmichalk.querySpecification.findable;

import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.models.EdgeToNode;
import cz.muni.xmichalk.models.SubgraphWrapper;
import cz.muni.xmichalk.querySpecification.ICondition;
import cz.muni.xmichalk.util.GraphTraverser;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class FilteredSubgraphs implements IFindableSubgraph {
    public ICondition<EdgeToNode> filter;
    public IFindableSubgraph startsIn = new WholeGraph();

    public FilteredSubgraphs() {
    }

    public FilteredSubgraphs(ICondition<EdgeToNode> filter) {
        this.filter = filter;
    }


    public FilteredSubgraphs(ICondition<EdgeToNode> filter, IFindableSubgraph startsIn) {
        this.filter = filter;
        this.startsIn = startsIn;
    }

    @Override public List<SubgraphWrapper> find(SubgraphWrapper graph, INode startNode) {
        if (filter == null) {
            throw new IllegalStateException("Value of filter cannot be null in " + this.getClass().getSimpleName());
        }
        if (startsIn == null) {
            throw new IllegalStateException("Value of startsIn cannot be null in " + this.getClass().getSimpleName());
        }

        Set<INode> startingNodes =
                startsIn.find(graph, startNode).stream().flatMap(subgraph -> subgraph.getNodes().stream())
                        .collect(Collectors.toSet());

        return startingNodes.stream().map(startingNode -> {
            SubgraphWrapper foundSubgraph = new SubgraphWrapper();

            GraphTraverser.traverseFrom(
                    startingNode, edgeToNode -> {
                        if (edgeToNode.node != null && !foundSubgraph.getNodes().contains(edgeToNode.node)) {
                            foundSubgraph.getNodes().add(edgeToNode.node);
                        }
                        if (edgeToNode.edge != null && !foundSubgraph.getEdges().contains(edgeToNode.edge)) {
                            foundSubgraph.getEdges().add(edgeToNode.edge);
                        }
                    }, filter
            );

            return foundSubgraph;
        }).toList();
    }
}
