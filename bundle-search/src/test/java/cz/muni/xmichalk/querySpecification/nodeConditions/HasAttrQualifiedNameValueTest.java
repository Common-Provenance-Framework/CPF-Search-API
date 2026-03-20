package cz.muni.xmichalk.querySpecification.nodeConditions;

import cz.muni.fi.cpm.merged.MergedNode;
import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.models.QualifiedNameData;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.openprovenance.prov.vanilla.Other;

import java.util.List;
import java.util.stream.Stream;

import static cz.muni.xmichalk.util.NameSpaceConstants.PROV_URI;

public class HasAttrQualifiedNameValueTest {
    private static final INode node = new MergedNode(new org.openprovenance.prov.vanilla.Entity(
            new QualifiedNameData("http://example.org/", "entity1").toQN(), List.of(new Other(
            new QualifiedNameData("attr/", "Name").toQN(),
            new QualifiedNameData(PROV_URI, "QUALIFIED_NAME").toQN(),
            new QualifiedNameData("attr/", "Value").toQN()

    ))
    ));

    private static Stream<Object[]> testParams() {
        return Stream.of(
                new Object[]{node, "attr/Name", "attr/Value", true},
                new Object[]{node, "attr/Name", ".*", true},
                new Object[]{node, "attr/Name", "attr/OtherValue", false},
                new Object[]{node, "attr/Other", "attr/Value", false}
        );
    }

    @ParameterizedTest @MethodSource("testParams")
    public void testHasAttrQualifiedNameValue(INode node, String attrName, String attrValue, boolean expectedResult) {
        HasAttrQualifiedNameValue condition = new HasAttrQualifiedNameValue(attrName, attrValue);
        assert condition.test(node) == expectedResult;
    }
}
