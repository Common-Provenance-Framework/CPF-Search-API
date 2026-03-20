package cz.muni.xmichalk.models;

import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.PriorityBlockingQueue;

public class TraversalState {
    public Set<Connection> traversedPreferred;
    public Set<Connection> traversedReferenced;
    public ConcurrentMap<Connection, ItemToTraverse> traversingPreferred;
    public ConcurrentMap<Connection, ItemToTraverse> traversingReferenced;
    public PriorityBlockingQueue<ItemToTraverse> toTraverseQueue;
    public ConcurrentLinkedQueue<ResultFromBundle> results;
    public ConcurrentLinkedQueue<String> errors;

    public TraversalState(
            Set<Connection> traversedPreferred,
            Set<Connection> traversedReferenced,
            ConcurrentMap<Connection, ItemToTraverse> traversingPreferred,
            ConcurrentMap<Connection, ItemToTraverse> traversingReferenced,
            PriorityBlockingQueue<ItemToTraverse> toTraverseQueue,
            ConcurrentLinkedQueue<ResultFromBundle> results,
            ConcurrentLinkedQueue<String> errors
    ) {
        this.traversedPreferred = traversedPreferred;
        this.traversedReferenced = traversedReferenced;
        this.traversingPreferred = traversingPreferred;
        this.traversingReferenced = traversingReferenced;
        this.toTraverseQueue = toTraverseQueue;
        this.results = results;
        this.errors = errors;
    }
}
