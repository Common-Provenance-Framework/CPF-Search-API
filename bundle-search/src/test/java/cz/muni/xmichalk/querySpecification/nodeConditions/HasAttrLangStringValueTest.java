package cz.muni.xmichalk.querySpecification.nodeConditions;

import cz.muni.fi.cpm.merged.MergedNode;
import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.models.QualifiedNameData;
import org.junit.jupiter.params.ParameterizedTest;
import org.openprovenance.prov.vanilla.Entity;
import org.openprovenance.prov.vanilla.LangString;
import org.openprovenance.prov.vanilla.Other;
import org.openprovenance.prov.vanilla.QualifiedName;

import java.util.List;
import java.util.stream.Stream;

import static cz.muni.xmichalk.util.NameSpaceConstants.SCHEMA_URI;

public class HasAttrLangStringValueTest {
    private static final INode node = new MergedNode(new Entity(
            new QualifiedNameData("example.org/", "entity1").toQN(), List.of(new Other(
            new QualifiedName(SCHEMA_URI, "name", "schema"),
            new QualifiedName("http://www.w3.org/2001/XMLSchema#", "string", "xsd"),
            new LangString("Value", "Lang")
    ))
    ));

    private static Stream<Object[]> testParams() {
        return Stream.of(
                new Object[]{SCHEMA_URI + "name", "Value", null, true},
                new Object[]{SCHEMA_URI + "name", ".*", ".*", true},
                new Object[]{SCHEMA_URI + "name", "Value", "Lang", true},
                new Object[]{SCHEMA_URI + "name", null, "Lang", true},
                new Object[]{SCHEMA_URI + "name", "OtherValue", "Lang", false},
                new Object[]{SCHEMA_URI + "name", "Value", "OtherLang", false},
                new Object[]{"other/name", "Value", "Lang", false}
        );
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams")
    public void testHasAttrLangStringValue(
            String attrName,
            String valueRegex,
            String langRegex,
            boolean expectedResult
    ) {

        HasAttrLangStringValue hasAttrLangStringValue = new HasAttrLangStringValue(attrName, langRegex, valueRegex);

        assert hasAttrLangStringValue.test(node) == expectedResult;

    }
}
