package cz.muni.xmichalk.querySpecification.findable;

import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.models.SubgraphWrapper;

import java.util.List;

public class WholeGraph implements IFindableSubgraph {

    @Override public List<SubgraphWrapper> find(final SubgraphWrapper graph, final INode startNode) {
        return List.of(graph);
    }
}
