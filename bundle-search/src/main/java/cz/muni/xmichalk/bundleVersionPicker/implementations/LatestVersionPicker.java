package cz.muni.xmichalk.bundleVersionPicker.implementations;

import cz.muni.fi.cpm.model.CpmDocument;
import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.bundleVersionPicker.IVersionPicker;
import cz.muni.xmichalk.util.AttributeUtils;
import cz.muni.xmichalk.util.GraphTraverser;
import org.openprovenance.prov.model.LangString;
import org.openprovenance.prov.model.QualifiedName;

import java.util.Set;

import static cz.muni.xmichalk.util.AttributeNames.ATTR_PROV_TYPE;
import static cz.muni.xmichalk.util.AttributeNames.ATTR_VERSION;
import static cz.muni.xmichalk.util.NameSpaceConstants.PROV_URI;

public class LatestVersionPicker implements IVersionPicker {
    public LatestVersionPicker() {
    }

    @Override public QualifiedName apply(QualifiedName bundleId, CpmDocument metaDocument) {
        if (metaDocument == null) {
            throw new RuntimeException("Meta document is null");
        }

        INode versionNode = pickLatestVersionNode(metaDocument);

        return versionNode != null ? versionNode.getId() : null;
    }

    public static INode pickLatestVersionNode(CpmDocument metaDocument) {

        Set<INode> versionNodes = GraphTraverser.traverseAndFindNodes(
                metaDocument.getNodes().getFirst(),
                (node) -> hasProvTypeBundle(node) &&
                        hasVersionAttribute(node)
        );

        if (versionNodes == null || versionNodes.isEmpty()) {
            return null;
        }

        int latestVersion = 0;
        INode latestVersionNode = null;

        for (INode node : versionNodes) {
            String versionString = ((String) AttributeUtils.getAttributeValue(node, ATTR_VERSION));
            double version = Double.parseDouble(versionString);

            if (version > latestVersion) {
                latestVersion = (int) version;
                latestVersionNode = node;
            }
        }

        return latestVersionNode;
    }


    private static boolean hasProvTypeBundle(INode node) {
        return AttributeUtils.hasAttributeTargetValue(
                node,
                ATTR_PROV_TYPE,
                QualifiedName.class,
                qn -> qn.getUri().equals(PROV_URI + "bundle")
        ) || AttributeUtils.hasAttributeTargetValue(
                node,
                ATTR_PROV_TYPE,
                LangString.class,
                langString -> langString.getValue().equals("prov:bundle")
        );
    }

    private static boolean hasVersionAttribute(INode node) {
        return AttributeUtils.hasAttributeTargetValue(node, ATTR_VERSION, String.class, v -> true);
    }
}
