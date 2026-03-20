package cz.muni.xmichalk.querySpecification.subgraphConditions.edgeConditions;

import cz.muni.fi.cpm.merged.MergedEdge;
import cz.muni.fi.cpm.model.IEdge;
import org.junit.jupiter.params.ParameterizedTest;
import org.openprovenance.prov.model.StatementOrBundle;

import java.util.stream.Stream;

public class IsRelationTest {
    static Stream<Object[]> testParams() {
        return Stream.of(
                new Object[]{StatementOrBundle.Kind.PROV_DERIVATION, StatementOrBundle.Kind.PROV_DERIVATION, true},
                new Object[]{StatementOrBundle.Kind.PROV_DERIVATION, StatementOrBundle.Kind.PROV_SPECIALIZATION, false},
                new Object[]{StatementOrBundle.Kind.PROV_DERIVATION, StatementOrBundle.Kind.PROV_ENTITY, false},
                new Object[]{StatementOrBundle.Kind.PROV_DERIVATION, StatementOrBundle.Kind.PROV_ACTIVITY, false},
                new Object[]{StatementOrBundle.Kind.PROV_DERIVATION, StatementOrBundle.Kind.PROV_AGENT, false}
        );
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams") public void testIsRelation(
            StatementOrBundle.Kind actualRelation,
            StatementOrBundle.Kind comparedRelation,
            boolean expectedResult
    ) {
        IEdge edge = new MergedEdge(() -> actualRelation);

        IsRelation isRelationCondition = new IsRelation(comparedRelation);

        assert isRelationCondition.test(edge) == expectedResult;
    }
}
