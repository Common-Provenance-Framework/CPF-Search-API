package cz.muni.xmichalk.models;

import cz.muni.fi.cpm.model.CpmDocument;
import cz.muni.fi.cpm.model.IEdge;
import cz.muni.fi.cpm.model.INode;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class SubgraphWrapper {
    private final List<INode> nodes;
    private final List<IEdge> edges;

    public SubgraphWrapper() {
        this.nodes = new ArrayList<>();
        this.edges = new ArrayList<>();
    }

    public SubgraphWrapper(Collection<INode> nodes, Collection<IEdge> edges) {
        this.nodes = new ArrayList<>(nodes);
        this.edges = new ArrayList<>(edges);
    }

    public SubgraphWrapper(SubgraphWrapper other) {
        this.nodes = new ArrayList<>(other.getNodes());
        this.edges = new ArrayList<>(other.getEdges());
    }

    public SubgraphWrapper(CpmDocument cpmDocument) {
        this.nodes = new ArrayList<>(cpmDocument.getNodes());
        this.edges = new ArrayList<>(cpmDocument.getEdges());
    }

    public List<INode> getNodes() {
        return nodes;
    }

    public List<IEdge> getEdges() {
        return edges;
    }
}
