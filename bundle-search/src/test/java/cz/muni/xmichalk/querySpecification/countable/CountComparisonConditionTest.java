package cz.muni.xmichalk.querySpecification.countable;

import org.junit.jupiter.params.ParameterizedTest;

import java.util.stream.Stream;

public class CountComparisonConditionTest {

    static Stream<Object[]> testParams() {
        return Stream.of(
                new Object[]{1, EComparisonResult.LESS_THAN, 5, true},
                new Object[]{1, EComparisonResult.LESS_THAN, 0, false},
                new Object[]{1, EComparisonResult.LESS_THAN_OR_EQUALS, 1, true},
                new Object[]{1, EComparisonResult.LESS_THAN_OR_EQUALS, 5, true},
                new Object[]{1, EComparisonResult.LESS_THAN_OR_EQUALS, 0, false},
                new Object[]{1, EComparisonResult.EQUALS, 1, true},
                new Object[]{1, EComparisonResult.EQUALS, 5, false},
                new Object[]{1, EComparisonResult.GREATER_THAN_OR_EQUALS, 1, true},
                new Object[]{5, EComparisonResult.GREATER_THAN_OR_EQUALS, 1, true},
                new Object[]{1, EComparisonResult.GREATER_THAN_OR_EQUALS, 5, false},
                new Object[]{5, EComparisonResult.GREATER_THAN, 1, true},
                new Object[]{1, EComparisonResult.GREATER_THAN, 5, false}

        );
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams")
    public void testCountComparisonCondition(
            int first,
            EComparisonResult comparisonResult,
            int second,
            boolean expectedResult
    ) {
        CountComparisonCondition<Object> countComparisonCondition =
                new CountComparisonCondition<Object>(_ -> first, comparisonResult, _ -> second);

        assert countComparisonCondition.test(null) == expectedResult;

    }
}
