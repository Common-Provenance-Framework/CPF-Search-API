package cz.muni.xmichalk.querySpecification.findable;

import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.models.SubgraphWrapper;

import java.util.ArrayList;
import java.util.List;

public class StartNode implements IFindableSubgraph {
    @Override public List<SubgraphWrapper> find(final SubgraphWrapper graph, final INode startNode) {
        return List.of(new SubgraphWrapper(List.of(startNode), new ArrayList<>()));
    }
}
