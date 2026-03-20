package cz.muni.xmichalk.querySpecification.nodeConditions;

import cz.muni.fi.cpm.merged.MergedNode;
import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.models.QualifiedNameData;
import org.junit.jupiter.params.ParameterizedTest;
import org.openprovenance.prov.model.*;

import java.util.ArrayList;
import java.util.stream.Stream;

public class IsKindTest {
    private static final Activity activity = new org.openprovenance.prov.vanilla.Activity(
            new QualifiedNameData(
                    "http://example.org/",
                                  "activity1"
            ).toQN(), null, null, new ArrayList<>()
    );

    private static final Entity entity = new org.openprovenance.prov.vanilla.Entity(
            new QualifiedNameData("http://example.org/", "entity1").toQN(),
            new ArrayList<>()
    );

    private static final Agent agent = new org.openprovenance.prov.vanilla.Agent(
            new QualifiedNameData("http://example.org/", "agent1").toQN(),
            new ArrayList<>()
    );

    static Stream<Object[]> testParams() {
        return Stream.of(
                new Object[]{entity, StatementOrBundle.Kind.PROV_ENTITY, true},
                new Object[]{activity, StatementOrBundle.Kind.PROV_ACTIVITY, true},
                new Object[]{agent, StatementOrBundle.Kind.PROV_AGENT, true},
                new Object[]{entity, StatementOrBundle.Kind.PROV_AGENT, false},
                new Object[]{activity, StatementOrBundle.Kind.PROV_ENTITY, false},
                new Object[]{agent, StatementOrBundle.Kind.PROV_ACTIVITY, false}

        );
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams")
    public void testIsKind(Element element, StatementOrBundle.Kind kind, boolean expectedResult) {
        INode node = new MergedNode(element);

        IsKind isKindCondition = new IsKind(kind);

        assert isKindCondition.test(node) == expectedResult;
    }
}
