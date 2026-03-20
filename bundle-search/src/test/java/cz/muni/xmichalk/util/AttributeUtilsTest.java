package cz.muni.xmichalk.util;

import cz.muni.fi.cpm.merged.CpmMergedFactory;
import cz.muni.fi.cpm.model.CpmDocument;
import cz.muni.fi.cpm.model.ICpmFactory;
import cz.muni.fi.cpm.model.ICpmProvFactory;
import cz.muni.fi.cpm.model.INode;
import cz.muni.fi.cpm.vanilla.CpmProvFactory;
import cz.muni.xmichalk.TestDocumentProvider;
import org.junit.jupiter.api.Test;
import org.openprovenance.prov.model.*;
import org.openprovenance.prov.vanilla.ProvFactory;

import javax.xml.datatype.XMLGregorianCalendar;
import java.util.List;

import static cz.muni.xmichalk.util.NameSpaceConstants.BLANK_URI;
import static cz.muni.xmichalk.util.NameSpaceConstants.PROV_URI;

public class AttributeUtilsTest {
    static ProvFactory pF = new ProvFactory();
    static ICpmFactory cF = new CpmMergedFactory(pF);
    static ICpmProvFactory cPF = new CpmProvFactory(pF);

    @Test public void testGetAttributeValue_location() {
        CpmDocument cpmDoc = TestDocumentProvider.samplingBundle_V1;
        INode node = cpmDoc.getNode(new org.openprovenance.prov.vanilla.QualifiedName(
                "gen/",
                                                                                      "190fd43b1968737f3501420a6bfd9b74873e32416c6e14fef26238fbe3b197a2",
                                                                                      "gen"
        ));

        Object value = AttributeUtils.getAttributeValue(node, AttributeNames.ATTR_LOCATION);

        assert value != null;
        assert value instanceof List;
        List<?> locations = (List<?>) value;
        assert locations.size() == 1;
        Object locationObj = locations.get(0);
        assert locationObj instanceof Location;
        Location loc = (Location) locationObj;
        assert loc.getValue() instanceof LangString;
        LangString langString = (LangString) loc.getValue();
        assert langString.getValue().equals("marineregions:3293");

    }

    @Test public void testGetAttributeValue_provType() {
        QualifiedName entityId = new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "entity1", "blank");
        Entity entity = cPF.getProvFactory().newEntity(entityId);
        QualifiedName typeValue = pF.newQualifiedName(BLANK_URI, "MyType", "blank");
        Type typeAttr = pF.newType(
                typeValue,
                new org.openprovenance.prov.vanilla.QualifiedName(PROV_URI, "QUALIFIED_NAME", "prov")
        );
        entity.getType().add(typeAttr);


        Object type = AttributeUtils.getAttributeValue(entity, AttributeNames.ATTR_PROV_TYPE);

        assert type != null;
        assert type instanceof QualifiedName;
        QualifiedName qnType = (QualifiedName) type;
        assert qnType.getUri().equals(typeValue.getUri());
    }

    @Test public void testGetAttributeValue_startTime() {
        QualifiedName activityId = new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "activity1", "blank");
        Activity activity = cPF.getProvFactory().newActivity(activityId);
        var startTime = pF.newISOTime("2025-08-16T10:00:00Z");
        activity.setStartTime(startTime);

        Object timestamp = AttributeUtils.getAttributeValue(activity, AttributeNames.ATTR_START_TIME);

        assert timestamp != null;
        assert timestamp instanceof XMLGregorianCalendar;
        XMLGregorianCalendar xmlTime = (XMLGregorianCalendar) timestamp;
        assert xmlTime.equals(startTime);

    }

    @Test public void testHasAttributeTargetValue_provType_true() {
        CpmDocument cpmDoc = TestDocumentProvider.samplingBundle_V1;
        INode node = cpmDoc.getNode(new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "Sampling", "blank"));
        QualifiedName attributeName =
                new org.openprovenance.prov.vanilla.QualifiedName(NameSpaceConstants.PROV_URI, "type", "prov");

        boolean hasTargetValue = AttributeUtils.hasAttributeTargetValue(
                node,
                attributeName,
                QualifiedName.class,
                qn -> qn.getUri()
                        .equals(NameSpaceConstants.CPM_URI +
                                        "mainActivity")
        );

        assert hasTargetValue;
    }

    @Test public void testHasAttributeTargetValue_provType_false() {
        CpmDocument cpmDoc = TestDocumentProvider.samplingBundle_V1;
        INode node = cpmDoc.getNode(new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "Sampling", "blank"));
        QualifiedName attributeName =
                new org.openprovenance.prov.vanilla.QualifiedName(NameSpaceConstants.PROV_URI, "type", "prov");

        boolean hasTargetValue = AttributeUtils.hasAttributeTargetValue(
                node,
                attributeName,
                QualifiedName.class,
                qn -> qn.getUri()
                        .equals(NameSpaceConstants.CPM_URI +
                                        "backwardConnector")
        );

        assert !hasTargetValue;
    }

    @Test public void testIsTargetValue_provType_true() {
        QualifiedName value = pF.newQualifiedName(BLANK_URI, "value", "blank");

        boolean isTargetValue =
                AttributeUtils.isTargetValue(value, QualifiedName.class, qn -> qn.getUri().equals(value.getUri()));

        assert isTargetValue;
    }

    @Test public void testIsTargetValue_provType_false() {
        QualifiedName value = pF.newQualifiedName(BLANK_URI, "value", "blank");

        boolean isTargetValue =
                AttributeUtils.isTargetValue(value, QualifiedName.class, qn -> qn.getUri().equals("otherUri"));

        assert !isTargetValue;
    }

    @Test public void testIsTargetValue_provTypeList_true() {
        QualifiedName value = pF.newQualifiedName(BLANK_URI, "value", "blank");

        boolean isTargetValue = AttributeUtils.isTargetValue(
                List.of(value),
                QualifiedName.class,
                qn -> qn.getUri().equals(value.getUri())
        );

        assert isTargetValue;
    }

    @Test public void testIsTargetValue_provTypeList_false() {
        QualifiedName value = pF.newQualifiedName(BLANK_URI, "value", "blank");

        boolean isTargetValue =
                AttributeUtils.isTargetValue(List.of(value), QualifiedName.class, qn -> qn.getUri().equals("otherUri"));

        assert !isTargetValue;
    }

}
