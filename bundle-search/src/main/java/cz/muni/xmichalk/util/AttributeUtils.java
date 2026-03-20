package cz.muni.xmichalk.util;

import cz.muni.fi.cpm.model.INode;
import org.openprovenance.prov.model.*;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.Predicate;

import static cz.muni.xmichalk.util.AttributeNames.*;

public class AttributeUtils {
    public static Object getAttributeValue(INode node, QualifiedName attributeName) {
        return getAttributeValue(node, attributeName.getUri());
    }

    public static Object getAttributeValue(INode node, String attributeNameUri) {
        List<Object> values = new ArrayList<>();
        boolean isList = false;
        boolean found = false;

        for (Element element : node.getElements()) {
            Object value = getAttributeValue(element, attributeNameUri);
            if (value == null) {
                continue;
            }

            found = true;
            if (value instanceof Collection) {
                isList = true;
                values.addAll((Collection<?>) value);
            } else {
                values.add(value);
            }
        }

        if (!found) return null; // does not have the attribute
        if (isList) return values; // found list(s) of values (possibly empty)
        if (values.size() == 1) return values.getFirst(); // only found one value instance and not a list
        return values; // multiple single values found
    }


    public static Object getAttributeValue(Element element, QualifiedName attributeName) {
        return getAttributeValue(element, attributeName.getUri());
    }

    public static Object getAttributeValue(Element element, String attributeNameUri) {
        if (element.getKind() == StatementOrBundle.Kind.PROV_ACTIVITY) {
            if (attributeNameUri.equals(ATTR_START_TIME.getUri())) {
                return ((Activity) element).getStartTime();
            } else if (attributeNameUri.equals(ATTR_END_TIME.getUri())) {
                return ((Activity) element).getEndTime();
            }
        }
        if (attributeNameUri.equals(ATTR_LOCATION.getUri())) {
            return element.getLocation();
        }
        if (attributeNameUri.equals(ATTR_PROV_TYPE.getUri())) {
            for (Type type : element.getType()) {
                if (type.getElementName().getUri().equals(attributeNameUri)) {
                    return type.getValue();
                }
            }
        }
        if (attributeNameUri.equals(ATTR_LABEL.getUri())) {
            if (element.getLabel() != null) {
                return element.getLabel();
            }
        }
        for (Other other : element.getOther()) {
            QualifiedName name = other.getElementName();
            if (name.getUri().equals(attributeNameUri)) {
                return other.getValue();
            }
        }

        return null;
    }

    public static <T> boolean hasAttributeTargetValue(
            INode node,
            QualifiedName attributeName,
            Class<T> targetClass,
            Predicate<T> isTargetValue
    ) {
        return hasAttributeTargetValue(node, attributeName.getUri(), targetClass, isTargetValue);
    }

    public static <T> boolean hasAttributeTargetValue(
            INode node,
            String attributeNameUri,
            Class<T> targetClass,
            Predicate<T> isTargetValue
    ) {
        Object value = getAttributeValue(node, attributeNameUri);
        return isTargetValue(value, targetClass, isTargetValue);
    }


    public static <T> boolean isTargetValue(Object value, Class<T> targetClass, Predicate<T> predicate) {

        if (targetClass.isInstance(value)) {
            return predicate.test(targetClass.cast(value));
        }

        if (value instanceof Collection) {
            for (Object item : (Collection<?>) value) {
                if (targetClass.isInstance(item)) {
                    if (predicate.test(targetClass.cast(item))) {
                        return true;
                    }
                }
            }
            return false;
        }

        return false;
    }
}
