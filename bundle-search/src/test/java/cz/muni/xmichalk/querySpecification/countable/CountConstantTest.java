package cz.muni.xmichalk.querySpecification.countable;

import org.junit.jupiter.params.ParameterizedTest;

import java.util.stream.IntStream;
import java.util.stream.Stream;

public class CountConstantTest {
    static Stream<Object[]> testParams() {
        return IntStream.rangeClosed(0, 10).mapToObj(i -> new Object[]{i});
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams")
    public <T> void testCountConstant(int count) {
        CountConstant<T> countConstant = new CountConstant<T>(count);

        assert countConstant.count(null) == count;

    }

}
