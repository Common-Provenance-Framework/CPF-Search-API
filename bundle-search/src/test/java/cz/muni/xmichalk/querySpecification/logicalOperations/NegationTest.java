package cz.muni.xmichalk.querySpecification.logicalOperations;

import cz.muni.xmichalk.querySpecification.ICondition;
import org.junit.jupiter.params.ParameterizedTest;

import java.util.stream.Stream;

public class NegationTest {
    static Stream<Object[]> testParams() {
        return Stream.of(
                new Object[]{"XXX", (ICondition<String>) (str) -> str.equals("YYY"), true},
                new Object[]{"XXX", (ICondition<String>) (str) -> str.equals("XXX"), false},
                new Object[]{5, (ICondition<Integer>) (number) -> number == 0, true},
                new Object[]{5, (ICondition<Integer>) (number) -> number > 0, false}
        );
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams")
    public <T> void testNegation(T target, ICondition<T> condition, boolean expectedResult) {

        Negation<T> negation = new Negation<T>(condition);

        assert negation.test(target) == expectedResult;
    }
}