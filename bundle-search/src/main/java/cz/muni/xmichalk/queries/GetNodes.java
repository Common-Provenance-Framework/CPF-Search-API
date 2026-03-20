package cz.muni.xmichalk.queries;

import com.fasterxml.jackson.databind.JsonNode;
import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.models.SubgraphWrapper;
import cz.muni.xmichalk.querySpecification.findable.IFindableSubgraph;
import cz.muni.xmichalk.storage.EBundlePart;
import cz.muni.xmichalk.util.ResultsTransformationUtils;
import org.openprovenance.prov.model.Document;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class GetNodes extends FindSubgraphsQuery<JsonNode> {
    public GetNodes() {
    }

    public GetNodes(IFindableSubgraph fromSubgraphs) {
        this.fromSubgraphs = fromSubgraphs;
    }

    @Override protected EBundlePart decideRequiredBundlePart() {
        return EBundlePart.Whole;
    }

    @Override protected JsonNode transformResult(final List<SubgraphWrapper> subgraphs) {
        if (subgraphs == null || subgraphs.isEmpty()) {
            return null;
        }

        Set<INode> nodes =
                subgraphs.stream().flatMap(subgraph -> subgraph.getNodes().stream()).collect(Collectors.toSet());

        if (nodes.isEmpty()) {
            return null;
        }

        Document encapsulatingDocument = ResultsTransformationUtils.encapsulateInDocument(nodes, null);
        return ResultsTransformationUtils.transformToJsonNode(encapsulatingDocument);
    }
}
