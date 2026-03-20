package cz.muni.xmichalk.querySpecification.logicalOperations;

import cz.muni.xmichalk.querySpecification.ICondition;
import org.junit.jupiter.params.ParameterizedTest;

import java.util.List;
import java.util.stream.Stream;

public class AllTrueTest {

    private static Stream<Object[]> testParams() {
        return Stream.of(
                new Object[]{"X", List.of((ICondition<String>) x -> x.equals("X")), true},
                new Object[]{"X", List.of((ICondition<String>) _ -> true), true},
                new Object[]{"X", List.of(_ -> true, (ICondition<String>) _ -> true), true},
                new Object[]{"X", List.of((ICondition<String>) x -> x.equals("Y")), false},
                new Object[]{"X", List.of((ICondition<String>) _ -> false), false},
                new Object[]{"X", List.of(_ -> true, (ICondition<String>) _ -> false), false},
                new Object[]{"X", List.of(_ -> true, _ -> false, (ICondition<String>) _ -> true), false}
        );
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams")
    public <T> void test(T target, List<ICondition<T>> conditions, boolean expectedResult) {
        AllTrue<T> allTrue = new AllTrue<T>(conditions);

        assert allTrue.test(target) == expectedResult;
    }
}
