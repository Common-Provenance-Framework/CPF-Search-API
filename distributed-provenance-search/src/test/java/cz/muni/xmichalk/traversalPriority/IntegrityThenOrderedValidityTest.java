package cz.muni.xmichalk.traversalPriority;

import cz.muni.xmichalk.models.ItemToTraverse;
import cz.muni.xmichalk.validity.EValidityCheck;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.openprovenance.prov.vanilla.QualifiedName;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public class IntegrityThenOrderedValidityTest {
    private static final QualifiedName bundleA = new QualifiedName("http://example.org/", "bundleA", "ex");
    private static final QualifiedName bundleB = new QualifiedName("http://example.org/", "bundleB", "ex");
    private static final QualifiedName connA = new QualifiedName("http://example.org/", "connA", "ex");
    private static final QualifiedName connB = new QualifiedName("http://example.org/", "connB", "ex");

    static Stream<Object[]> testParams() {
        return Stream.of(
                new Object[]{
                        "01", new ItemToTraverse(
                        bundleA,
                        connA,
                        null,
                        "http://prov-service.com/",
                        true,
                        List.of(Map.entry(EValidityCheck.DEMO_SIMPLE_CONSTRAINTS, true))
                ), new ItemToTraverse(
                        bundleB,
                        connB,
                        null,
                        "http://prov-service.com/",
                        false,
                        List.of(Map.entry(EValidityCheck.DEMO_SIMPLE_CONSTRAINTS, true))
                ), -1
                }, new Object[]{
                        "02", new ItemToTraverse(
                        bundleB,
                        connB,
                        null,
                        "http://prov-service.com/",
                        true,
                        List.of(Map.entry(EValidityCheck.DEMO_SIMPLE_CONSTRAINTS, false))
                ), new ItemToTraverse(
                        bundleA,
                        connA,
                        null,
                        "http://prov-service.com/",
                        false,
                        List.of(Map.entry(EValidityCheck.DEMO_SIMPLE_CONSTRAINTS, true))
                ), -1
                }, new Object[]{
                        "03", new ItemToTraverse(
                        bundleA,
                        connA,
                        null,
                        "http://prov-service.com/",
                        true,
                        List.of(Map.entry(EValidityCheck.DEMO_SIMPLE_CONSTRAINTS, true))
                ), new ItemToTraverse(
                        bundleB,
                        connB,
                        null,
                        "http://prov-service.com/",
                        false,
                        List.of(Map.entry(EValidityCheck.DEMO_SIMPLE_CONSTRAINTS, false))
                ), -1
                }, new Object[]{
                        "04", new ItemToTraverse(
                        bundleB, connB, null, "http://prov-service.com/", true, List.of(
                        Map.entry(EValidityCheck.DEMO_IS_PROCESSING_BUNDLE, true),
                        Map.entry(EValidityCheck.DEMO_IS_SAMPLING_BUNDLE, false)
                )
                ), new ItemToTraverse(
                        bundleA, connA, null, "http://prov-service.com/", true, List.of(
                        Map.entry(EValidityCheck.DEMO_IS_PROCESSING_BUNDLE, false),
                        Map.entry(EValidityCheck.DEMO_IS_SAMPLING_BUNDLE, true)
                )
                ), -1
                }

        );
    }

    @ParameterizedTest @MethodSource("testParams")
    public void testEnumValue(String id, ItemToTraverse a, ItemToTraverse b, int expectedResult) {
        Comparator<ItemToTraverse> comparator = new IntegrityThenOrderedValidity();

        int result = comparator.compare(a, b);
        int reversedResult = comparator.compare(b, a);

        assert result == expectedResult;
        assert reversedResult == (-1) * expectedResult;
    }
}
