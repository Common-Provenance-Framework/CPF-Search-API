package cz.muni.xmichalk.querySpecification.nodeConditions;

import cz.muni.fi.cpm.merged.MergedNode;
import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.models.QualifiedNameData;
import cz.muni.xmichalk.util.AttributeNames;
import org.junit.jupiter.api.Test;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import java.util.ArrayList;

public class HasAttrTimestampValueTest {

    private final INode activityNode = new MergedNode(new org.openprovenance.prov.vanilla.Activity(
            new QualifiedNameData("http://example.org/", "activity1").toQN(),
            DatatypeFactory.newInstance().newXMLGregorianCalendar("2025-08-16T10:00:00Z"),
            DatatypeFactory.newInstance().newXMLGregorianCalendar("2025-08-16T10:00:00Z"),
            new ArrayList<>()
    ));

    public HasAttrTimestampValueTest() throws DatatypeConfigurationException {
    }

    @Test public void testHasAttrTimestampValue_true() throws DatatypeConfigurationException {
        HasAttrTimestampValue condition = new HasAttrTimestampValue(
                AttributeNames.ATTR_START_TIME.getUri(),
                "2025-08-16T10:00:00Z",
                "2025-10-16T10:00:00Z",
                "2025-01-16T10:00:00Z"
        );

        assert condition.test(activityNode);
    }

    @Test public void testHasAttrTimestampValue_isBefore_false() throws DatatypeConfigurationException {
        HasAttrTimestampValue condition = new HasAttrTimestampValue(
                AttributeNames.ATTR_START_TIME.getUri(),
                "2025-08-16T10:00:00Z",
                "2025-08-16T10:00:00Z",
                "2025-01-16T10:00:00Z"
        );

        assert !condition.test(activityNode);
    }

    @Test public void testHasAttrTimestampValue_isAfter_false() throws DatatypeConfigurationException {
        HasAttrTimestampValue condition = new HasAttrTimestampValue(
                AttributeNames.ATTR_START_TIME.getUri(),
                "2025-08-16T10:00:00Z",
                "2025-10-16T10:00:00Z",
                "2025-08-16T10:00:00Z"
        );

        assert !condition.test(activityNode);
    }

    @Test public void testHasAttrTimestampValue_isEqual_false() throws DatatypeConfigurationException {
        HasAttrTimestampValue condition = new HasAttrTimestampValue(
                AttributeNames.ATTR_START_TIME.getUri(),
                "2025-10-16T10:00:00Z",
                "2025-10-16T10:00:00Z",
                "2025-01-16T10:00:00Z"
        );

        assert !condition.test(activityNode);
    }

}
