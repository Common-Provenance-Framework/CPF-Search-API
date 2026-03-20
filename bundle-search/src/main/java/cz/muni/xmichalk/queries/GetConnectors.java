package cz.muni.xmichalk.queries;

import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.models.*;
import cz.muni.xmichalk.querySpecification.findable.FittingNodes;
import cz.muni.xmichalk.querySpecification.findable.IFindableSubgraph;
import cz.muni.xmichalk.querySpecification.nodeConditions.HasAttrQualifiedNameValue;
import cz.muni.xmichalk.storage.EBundlePart;
import cz.muni.xmichalk.util.AttributeUtils;
import cz.muni.xmichalk.util.CpmUtils;
import org.openprovenance.prov.model.LangString;
import org.openprovenance.prov.model.QualifiedName;

import java.nio.file.AccessDeniedException;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static cz.muni.xmichalk.util.AttributeNames.*;
import static cz.muni.xmichalk.util.NameSpaceConstants.CPM_URI;

public class GetConnectors extends FindSubgraphsQuery<List<ConnectorData>> {
    public Boolean backward = null;

    public GetConnectors() {
    }

    public GetConnectors(Boolean backward) {
        this.backward = backward;
    }

    public GetConnectors(Boolean backward, IFindableSubgraph fromSubgraphs) {
        this.backward = backward;
        this.fromSubgraphs = fromSubgraphs;
    }

    @Override public QueryResult<List<ConnectorData>> evaluate(QueryContext context) throws AccessDeniedException {
        String typeValueRegex = backward == null ?
                CPM_URI + "(backward|forward)Connector" :
                CPM_URI + (backward ? "backwardConnector" : "forwardConnector");

        IFindableSubgraph finder =
                new FittingNodes(new HasAttrQualifiedNameValue(ATTR_PROV_TYPE.getUri(), typeValueRegex), fromSubgraphs);

        return super.evaluate(context, finder);
    }

    @Override public EBundlePart decideRequiredBundlePart() {
        return EBundlePart.TraversalInformation;
    }

    @Override protected List<ConnectorData> transformResult(List<SubgraphWrapper> subgraphs) {
        if (subgraphs == null || subgraphs.isEmpty()) {
            return List.of();
        }

        Set<INode> connectors =
                subgraphs.stream().flatMap(subgraph -> subgraph.getNodes().stream()).collect(Collectors.toSet());

        if (connectors.isEmpty()) {
            return List.of();
        }
        return connectors.stream().map(this::transformToConnectorData).toList();
    }

    private ConnectorData transformToConnectorData(INode node) {
        ConnectorData connectorData = new ConnectorData();


        connectorData.id = new QualifiedNameData().from(node.getId());

        INode referencedConnector = CpmUtils.getGeneralConnectorId(node);
        QualifiedName referencedConnectorIdValue =
                referencedConnector != null ? referencedConnector.getId() : node.getId();
        connectorData.referencedConnectorId = new QualifiedNameData().from(referencedConnectorIdValue);

        Object referencedBundleIdValue = AttributeUtils.getAttributeValue(node, ATTR_REFERENCED_BUNDLE_ID);
        connectorData.referencedBundleId = referencedBundleIdValue == null ?
                null :
                new QualifiedNameData().from((org.openprovenance.prov.model.QualifiedName) referencedBundleIdValue);

        Object referencedMetaBundleIdValue = AttributeUtils.getAttributeValue(node, ATTR_REFERENCED_META_BUNDLE_ID);
        connectorData.referencedMetaBundleId = referencedMetaBundleIdValue == null ?
                null :
                new QualifiedNameData().from((org.openprovenance.prov.model.QualifiedName) referencedMetaBundleIdValue);

        Object provServiceUriValue = AttributeUtils.getAttributeValue(node, ATTR_PROVENANCE_SERVICE_URI);
        connectorData.provenanceServiceUri =
                provServiceUriValue == null ? null : ((LangString) provServiceUriValue).getValue();


        LangString bundleHashValueObj =
                (LangString) AttributeUtils.getAttributeValue(node, ATTR_REFERENCED_BUNDLE_HASH_VALUE);
        connectorData.referencedBundleHashValue = bundleHashValueObj != null ? bundleHashValueObj.getValue() : null;

        LangString hashAlgObj = (LangString) AttributeUtils.getAttributeValue(node, ATTR_HASH_ALG);
        connectorData.hashAlg = hashAlgObj != null ? hashAlgObj.getValue() : null;

        return connectorData;
    }
}
