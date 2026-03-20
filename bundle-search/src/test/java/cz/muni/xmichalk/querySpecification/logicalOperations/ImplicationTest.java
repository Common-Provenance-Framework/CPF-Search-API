package cz.muni.xmichalk.querySpecification.logicalOperations;

import cz.muni.xmichalk.querySpecification.ICondition;
import org.junit.jupiter.params.ParameterizedTest;

import java.util.stream.Stream;

public class ImplicationTest {
    private static Stream<Object[]> testParams() {
        return Stream.of(
                new Object[]{
                        "X", (ICondition<String>) x -> x.equals("X"), (ICondition<String>) x -> x.equals("X"), true
                }, new Object[]{
                        "X", (ICondition<String>) x -> x.equals("Y"), (ICondition<String>) x -> x.equals("Y"), true
                }, new Object[]{
                        "X", (ICondition<String>) x -> x.equals("Y"), (ICondition<String>) x -> x.equals("X"), true
                }, new Object[]{
                        "X", (ICondition<String>) x -> x.equals("X"), (ICondition<String>) x -> x.equals("Y"), false
                }
        );
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams")
    public <T> void test(T target, ICondition<T> first, ICondition<T> second, boolean expectedResult) {
        Implication<T> implication = new Implication<>(first, second);

        assert implication.test(target) == expectedResult;
    }
}
