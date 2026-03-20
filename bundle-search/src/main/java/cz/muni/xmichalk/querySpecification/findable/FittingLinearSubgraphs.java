package cz.muni.xmichalk.querySpecification.findable;

import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.models.EdgeToNode;
import cz.muni.xmichalk.models.SubgraphWrapper;
import cz.muni.xmichalk.querySpecification.ICondition;
import cz.muni.xmichalk.util.LinearSubgraphFinder;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public class FittingLinearSubgraphs implements IFindableSubgraph {
    public List<ICondition<EdgeToNode>> graphParts;
    public IFindableSubgraph startsIn = new WholeGraph();

    public FittingLinearSubgraphs() {
    }

    public FittingLinearSubgraphs(List<ICondition<EdgeToNode>> graphParts) {
        this.graphParts = new ArrayList<>(graphParts);
    }

    public FittingLinearSubgraphs(List<ICondition<EdgeToNode>> graphParts, IFindableSubgraph startsIn) {
        this.graphParts = new ArrayList<>(graphParts);
        this.startsIn = startsIn;
    }

    @Override public List<SubgraphWrapper> find(SubgraphWrapper graph, INode startNode) {
        if (graphParts == null) {
            throw new IllegalStateException("Value of graphParts cannot be null in " + this.getClass().getSimpleName());
        }
        if (startsIn == null) {
            throw new IllegalStateException("Value of startsIn cannot be null in " + this.getClass().getSimpleName());
        }

        Set<INode> startingNodes =
                startsIn.find(graph, startNode).stream().flatMap(subgraph -> subgraph.getNodes().stream())
                        .collect(Collectors.toSet());


        List<Predicate<EdgeToNode>> graphSpecification = List.copyOf(graphParts);

        return startingNodes.stream()
                .map(startingNode -> LinearSubgraphFinder.findSubgraphsFrom(startingNode, graphSpecification))
                .flatMap(List::stream).collect(Collectors.toList());
    }
}
