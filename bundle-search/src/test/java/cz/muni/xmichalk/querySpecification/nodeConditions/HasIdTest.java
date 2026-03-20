package cz.muni.xmichalk.querySpecification.nodeConditions;

import cz.muni.fi.cpm.merged.MergedNode;
import cz.muni.fi.cpm.model.INode;
import org.junit.jupiter.params.ParameterizedTest;

import java.util.ArrayList;
import java.util.stream.Stream;

import static cz.muni.xmichalk.util.NameSpaceConstants.BLANK_URI;

public class HasIdTest {
    private static final INode entityNode =
            new MergedNode(new org.openprovenance.prov.vanilla.Entity(
                    new org.openprovenance.prov.vanilla.QualifiedName(
                            BLANK_URI,
                                                                      "entity1",
                                                                      "blank"
                    ), new ArrayList<>()
            ));

    static Stream<Object[]> testParams() {
        return Stream.of(
                new Object[]{entityNode, entityNode.getId().getUri(), true},
                new Object[]{entityNode, ".*", true},
                new Object[]{entityNode, "other", false}

        );
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams")
    public void testHasId(INode node, String idUriRegex, boolean expectedResult) {
        HasId hasIdCondition = new HasId(idUriRegex);

        assert hasIdCondition.test(node) == expectedResult;
    }
}
