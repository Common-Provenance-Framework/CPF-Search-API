package cz.muni.xmichalk.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import cz.muni.fi.cpm.model.IEdge;
import cz.muni.fi.cpm.model.INode;
import org.openprovenance.prov.model.*;
import org.openprovenance.prov.model.interop.Formats;
import org.openprovenance.prov.vanilla.HasAttributes;
import org.openprovenance.prov.vanilla.ProvFactory;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.function.Consumer;

import static cz.muni.xmichalk.util.NameSpaceConstants.BLANK_URI;

public class ResultsTransformationUtils {
    public static JsonNode transformToJsonNode(Document document) {
        ObjectMapper objectMapper = new ObjectMapper();

        String jsonString = ProvDocumentUtils.serialize(document, Formats.ProvFormat.JSON);
        try {
            return objectMapper.readTree(jsonString);
        } catch (IOException e) {
            throw new RuntimeException("Failed to convert document to JsonNode", e);
        }
    }

    public static Document encapsulateInDocument(Collection<INode> nodes, Collection<IEdge> edges) {
        ProvFactory pf = ProvFactory.getFactory();
        Document doc = pf.newDocument();

        Namespace ns = pf.newNamespace();

        Bundle bundle =
                pf.newNamedBundle(pf.newQualifiedName(BLANK_URI, "anonymous_encapsulating_bundle", "blank"), null);

        if (nodes == null) {
            nodes = List.of();
        }
        for (INode node : nodes) {
            if (node == null) {
                continue;
            }

            List<Element> elements = node.getElements();

            for (Element element : elements) {
                bundle.getStatement().add(element);
            }
        }

        if (edges == null) {
            edges = List.of();
        }
        for (IEdge edge : edges) {
            if (edge == null) {
                continue;
            }

            List<Relation> relations = edge.getRelations();

            for (Relation relation : relations) {
                bundle.getStatement().add(relation);
            }
        }

        registerAllPrefixes(ns, bundle);
        doc.setNamespace(ns);
        doc.getStatementOrBundle().add(bundle);

        return doc;
    }

    public static void registerAllPrefixes(Namespace namespace, Object provObject) {
        doForEachQualifiedName(provObject, qn -> namespace.register(qn.getPrefix(), qn.getNamespaceURI()));
    }

    public static void doForEachQualifiedName(Object provObject, Consumer<QualifiedName> action) {
        if (provObject instanceof Document doc) {
            for (StatementOrBundle statement : doc.getStatementOrBundle()) {
                doForEachQualifiedName(statement, action);
            }
        } else if (provObject instanceof Bundle bundle) {
            QualifiedName bundleId = bundle.getId();
            if (bundleId != null) {
                action.accept(bundleId);
            }
            for (Statement statement : bundle.getStatement()) {
                doForEachQualifiedName(statement, action);
            }
        } else if (provObject instanceof Identifiable identifiable) {
            QualifiedName id = identifiable.getId();
            if (id != null) {
                action.accept(id);
            }
        }

        if (provObject instanceof HasAttributes hasAttributes) {
            for (Attribute attr : hasAttributes.getAttributes()) {
                QualifiedName attrName = attr.getElementName();
                if (attrName != null) {
                    action.accept(attrName);
                }

                Object value = attr.getValue();
                if (value instanceof QualifiedName qnValue) {
                    action.accept(qnValue);
                }

                if (value instanceof List<?> listValue) {
                    for (Object item : listValue) {
                        if (item instanceof QualifiedName qnItem) {
                            action.accept(qnItem);
                        }
                    }
                }
            }
        }
    }
}
