package cz.muni.xmichalk.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;

import java.io.IOException;
import java.util.Iterator;
import java.util.Set;

public class ProvJsonUtils {


    public static String prepareJsonForDeserialization(String json) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode root = mapper.readTree(json);

            root = addExplicitBundleId(root);
            root = putTypedObjectsInArrays(root, mapper);
            root = putStringValuesInArray(root, mapper, false);
            root = stringifyValues(root, mapper);
            root = copyOuterPrefixesIntoBundles(root, mapper);


            return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(root);
        } catch (IOException e) {
            throw new RuntimeException("Failed to prepare JSON for deserialization", e);
        }
    }

    /**
     * Add explicit "@id" property to bundle to comply with provtoolbox deserialization requirements.
     *
     * @param root the original JSON, possibly without "@id" in bundle
     * @return the modified JSON Node with proper "@id" added to bundle
     */
    public static JsonNode addExplicitBundleId(JsonNode root) {
        JsonNode bundleNode = root.path("bundle");
        if (bundleNode.isObject()) {
            Iterator<String> fieldNames = bundleNode.fieldNames();
            if (fieldNames.hasNext()) {
                String bundleId = fieldNames.next();
                ObjectNode bundleObj = (ObjectNode) bundleNode.path(bundleId);
                if (!bundleObj.has("@id")) {
                    bundleObj.put("@id", bundleId);
                }
            }
        }
        return root;
    }

    /**
     * Removes "@id" property in bundle.
     *
     * @param json the original JSON, possibly with "@id" in bundle
     * @return the modified JSON string without "@id"
     */
    public static String removeExplicitBundleId(String json) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode root = mapper.readTree(json);

            JsonNode bundleNode = root.path("bundle");
            if (bundleNode.isObject()) {
                Iterator<String> fieldNames = bundleNode.fieldNames();
                if (fieldNames.hasNext()) {
                    String bundleId = fieldNames.next();
                    ObjectNode bundleObj = (ObjectNode) bundleNode.path(bundleId);

                    if (bundleObj.has("@id")) {
                        bundleObj.remove("@id");
                    }
                }
            }

            return mapper.writeValueAsString(root);
        } catch (IOException e) {
            throw new RuntimeException("Failed to remove explicit bundle id", e);
        }
    }

    private static JsonNode stringifyValues(JsonNode node, ObjectMapper mapper) {
        if (node.isObject()) {
            ObjectNode obj = mapper.createObjectNode();
            node.fieldNames().forEachRemaining(field -> {
                obj.set(field, stringifyValues(node.get(field), mapper));
            });
            return obj;
        } else if (node.isArray()) {
            ArrayNode arr = mapper.createArrayNode();
            node.forEach(item -> arr.add(stringifyValues(item, mapper)));
            return arr;
        } else {
            return new TextNode(node.asText());
        }
    }

    public static JsonNode copyOuterPrefixesIntoBundles(JsonNode root, ObjectMapper mapper) {
        JsonNode outerPrefix = root.path("prefix");
        JsonNode bundleNode = root.path("bundle");
        if (outerPrefix.isObject() && bundleNode.isObject()) {
            for (Iterator<String> it = bundleNode.fieldNames(); it.hasNext(); ) {
                String bundleId = it.next();
                ObjectNode bundleObj = (ObjectNode) bundleNode.path(bundleId);

                ObjectNode bundlePrefix = bundleObj.has("prefix") && bundleObj.get("prefix").isObject() ?
                        (ObjectNode) bundleObj.get("prefix") :
                        mapper.createObjectNode();

                outerPrefix.fields().forEachRemaining(entry -> {
                    bundlePrefix.set(entry.getKey(), entry.getValue());
                });

                bundleObj.set("prefix", bundlePrefix);
            }
        }

        return root;
    }

    private static JsonNode putTypedObjectsInArrays(JsonNode node, ObjectMapper mapper) {
        if (node.isObject()) {
            ObjectNode obj = (ObjectNode) node;

            boolean hasDollar = obj.has("$");
            boolean hasType = obj.has("type");

            // If object matches {"$", "type"} → wrap in array
            if (hasDollar && hasType) {
                ArrayNode arr = mapper.createArrayNode();
                arr.add(obj);
                return arr;
            }

            // Otherwise recurse through fields
            ObjectNode newObj = mapper.createObjectNode();
            obj.fields().forEachRemaining(e -> newObj.set(e.getKey(), putTypedObjectsInArrays(e.getValue(), mapper)));
            return newObj;
        }

        return node;
    }


    private static JsonNode putStringValuesInArray(JsonNode node, ObjectMapper mapper, boolean insideTarget) {

        if (node.isObject()) {
            ObjectNode obj = (ObjectNode) node;

            if (obj.has("$")) {
                return node;
            }

            Iterator<String> fieldNames = obj.fieldNames();
            while (fieldNames.hasNext()) {
                String fieldName = fieldNames.next();
                JsonNode child = obj.get(fieldName);

                boolean nowInsideTarget = insideTarget || Set.of("entity", "activity", "agent").contains(fieldName);

                if (nowInsideTarget) {
                    if (child.isTextual() && !fieldName.equals("prov:startTime") && !fieldName.equals("prov:endTime")) {
                        ArrayNode arr = mapper.createArrayNode();
                        arr.add(child.textValue());
                        obj.set(fieldName, arr);
                    }
                }
                putStringValuesInArray(child, mapper, nowInsideTarget);
            }
        }

        return node;
    }
}