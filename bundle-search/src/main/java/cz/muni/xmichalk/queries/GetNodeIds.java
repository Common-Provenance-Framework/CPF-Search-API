package cz.muni.xmichalk.queries;

import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.models.QualifiedNameData;
import cz.muni.xmichalk.models.SubgraphWrapper;
import cz.muni.xmichalk.querySpecification.findable.IFindableSubgraph;
import cz.muni.xmichalk.storage.EBundlePart;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class GetNodeIds extends FindSubgraphsQuery<List<QualifiedNameData>> {
    public GetNodeIds() {
    }

    public GetNodeIds(IFindableSubgraph fromSubgraphs) {
        this.fromSubgraphs = fromSubgraphs;
    }

    @Override protected EBundlePart decideRequiredBundlePart() {
        return EBundlePart.Whole;
    }

    @Override protected List<QualifiedNameData> transformResult(final List<SubgraphWrapper> subgraphs) {
        if (subgraphs == null || subgraphs.isEmpty()) {
            return List.of();
        }

        Set<INode> nodes =
                subgraphs.stream().flatMap(subgraph -> subgraph.getNodes().stream()).collect(Collectors.toSet());

        if (nodes.isEmpty()) {
            return List.of();
        }

        return nodes.stream().map(node -> new QualifiedNameData().from(node.getId())).toList();
    }
}
