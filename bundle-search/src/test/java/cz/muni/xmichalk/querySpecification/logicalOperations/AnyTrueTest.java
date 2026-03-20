package cz.muni.xmichalk.querySpecification.logicalOperations;

import cz.muni.xmichalk.querySpecification.ICondition;
import org.junit.jupiter.params.ParameterizedTest;

import java.util.List;
import java.util.stream.Stream;

public class AnyTrueTest {
    private static Stream<Object[]> testParams() {
        return Stream.of(
                new Object[]{"X", List.of((ICondition<String>) x -> x.equals("X")), true},
                new Object[]{"X", List.of((ICondition<String>) _ -> true), true},
                new Object[]{"X", List.of(_ -> true, (ICondition<String>) _ -> true), true},
                new Object[]{"X", List.of(_ -> true, _ -> false, (ICondition<String>) _ -> true), true},
                new Object[]{"X", List.of(_ -> true, (ICondition<String>) _ -> false), true},
                new Object[]{"X", List.of((ICondition<String>) _ -> false), false},
                new Object[]{"X", List.of((ICondition<String>) x -> x.equals("Y")), false}
        );
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams")
    public <T> void test(T target, List<ICondition<T>> conditions, boolean expectedResult) {
        AnyTrue<T> anyTrue = new AnyTrue<T>(conditions);

        assert anyTrue.test(target) == expectedResult;
    }
}
