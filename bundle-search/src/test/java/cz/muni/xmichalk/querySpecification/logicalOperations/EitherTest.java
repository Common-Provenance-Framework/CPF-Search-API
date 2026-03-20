package cz.muni.xmichalk.querySpecification.logicalOperations;

import cz.muni.xmichalk.querySpecification.ICondition;
import org.junit.jupiter.params.ParameterizedTest;

import java.util.stream.Stream;

public class EitherTest {
    private static Stream<Object[]> testParams() {
        return Stream.of(
                new Object[]{
                        "X", (ICondition<String>) x -> x.equals("X"), (ICondition<String>) x -> x.equals("Y"), true
                },
                new Object[]{"X", (ICondition<String>) _ -> true, (ICondition<String>) _ -> false, true},
                new Object[]{"X", (ICondition<String>) _ -> false, (ICondition<String>) _ -> true, true},
                new Object[]{"X", (ICondition<String>) _ -> true, (ICondition<String>) _ -> true, false},
                new Object[]{"X", (ICondition<String>) _ -> false, (ICondition<String>) _ -> false, false}
        );
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams")
    public <T> void test(T target, ICondition<T> first, ICondition<T> second, boolean expectedResult) {
        Either<T> either = new Either<>(first, second);

        assert either.test(target) == expectedResult;
    }
}
