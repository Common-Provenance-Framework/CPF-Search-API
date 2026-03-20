package cz.muni.xmichalk.util;

import cz.muni.fi.cpm.model.IEdge;
import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.models.EdgeToNode;
import cz.muni.xmichalk.models.SubgraphWrapper;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;

public class LinearSubgraphFinder {
    public static List<SubgraphWrapper> findSubgraphsFrom(
            INode startNode,
            List<Predicate<EdgeToNode>> subgraphSpecification
    ) {
        List<SubgraphWrapper> results = new ArrayList<>();

        recursiveFindSubgraph(
                new EdgeToNode(null, startNode),
                new SubgraphWrapper(),
                subgraphSpecification,
                new HashSet<>(),
                results
        );

        return results;
    }

    private static void recursiveFindSubgraph(
            EdgeToNode current,
            SubgraphWrapper foundPart,
            List<Predicate<EdgeToNode>> specification,
            Set<INode> visited,
            List<SubgraphWrapper> results
    ) {
        if (current == null) return;
        if (foundPart == null) foundPart = new SubgraphWrapper();

        IEdge edge = current.edge;
        INode node = current.node;
        int index = foundPart.getNodes().size();

        if (node == null) return;

        if (visited.contains(node)) return;
        visited.add(node);

        if (specification.size() <= index) return;

        if (!specification.get(index).test(current)) return;

        foundPart.getNodes().add(node);
        if (edge != null) foundPart.getEdges().add(edge);

        if (foundPart.getNodes().size() == specification.size()) {
            results.add(foundPart);
            return;
        }

        for (IEdge e : node.getCauseEdges()) {
            recursiveFindSubgraph(
                    new EdgeToNode(e, e.getEffect()),
                    new SubgraphWrapper(foundPart),
                    specification,
                    new HashSet<>(visited),
                    results
            );
        }
        for (IEdge e : node.getEffectEdges()) {
            recursiveFindSubgraph(
                    new EdgeToNode(e, e.getCause()),
                    new SubgraphWrapper(foundPart),
                    specification,
                    new HashSet<>(visited),
                    results
            );
        }
    }
}
