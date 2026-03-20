package cz.muni.xmichalk.querySpecification.subgraphConditions;

import cz.muni.fi.cpm.merged.MergedEdge;
import cz.muni.fi.cpm.merged.MergedNode;
import cz.muni.fi.cpm.model.INode;
import cz.muni.xmichalk.models.EdgeToNode;
import cz.muni.xmichalk.models.QualifiedNameData;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.openprovenance.prov.model.StatementOrBundle;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.stream.Stream;

import static cz.muni.xmichalk.util.NameSpaceConstants.BLANK_URI;

public class DerivationPathConditionTest {
    private static final INode node1 = new MergedNode(new org.openprovenance.prov.vanilla.Entity(
            new QualifiedNameData(
                    BLANK_URI,
                                  "entity1"
            ).toQN(), new ArrayList<>()
    ));

    private static final INode node2 = new MergedNode(new org.openprovenance.prov.vanilla.Entity(
            new QualifiedNameData(
                    BLANK_URI,
                                  "entity2"
            ).toQN(), new ArrayList<>()
    ));

    static Stream<Object[]> testParams() {
        return Arrays.stream(StatementOrBundle.Kind.values()).map(value -> new Object[]{value});
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("testParams")
    public void testDerivationPathCondition_pathKind(StatementOrBundle.Kind edgeKind) {
        EdgeToNode edgeToNode = new EdgeToNode(new MergedEdge(() -> edgeKind, node1, node2), node2);

        DerivationPathCondition derivationPathCondition = new DerivationPathCondition(null);

        boolean result = derivationPathCondition.test(edgeToNode);

        assert result == (edgeKind == StatementOrBundle.Kind.PROV_SPECIALIZATION ||
                edgeKind == StatementOrBundle.Kind.PROV_DERIVATION);
    }

    @Test public void testDerivationPathCondition_skipNullEdge() {
        EdgeToNode edgeToNode = new EdgeToNode(null, null);

        DerivationPathCondition derivationPathCondition = new DerivationPathCondition(null);

        assert derivationPathCondition.test(edgeToNode);
    }

    @Test public void testDerivationPathCondition_isEffectTrue() {
        EdgeToNode edgeToNode =
                new EdgeToNode(new MergedEdge(() -> StatementOrBundle.Kind.PROV_DERIVATION, node2, node1), node2);

        DerivationPathCondition derivationPathCondition = new DerivationPathCondition(false);

        assert derivationPathCondition.test(edgeToNode);
    }

    @Test public void testDerivationPathCondition_isEffectFalse() {
        EdgeToNode edgeToNode =
                new EdgeToNode(new MergedEdge(() -> StatementOrBundle.Kind.PROV_DERIVATION, node2, node1), node1);

        DerivationPathCondition derivationPathCondition = new DerivationPathCondition(false);

        assert !derivationPathCondition.test(edgeToNode);
    }

    @Test public void testDerivationPathCondition_isNotEffectTrue() {
        EdgeToNode edgeToNode =
                new EdgeToNode(new MergedEdge(() -> StatementOrBundle.Kind.PROV_DERIVATION, node2, node1), node1);

        DerivationPathCondition derivationPathCondition = new DerivationPathCondition(true);

        assert derivationPathCondition.test(edgeToNode);
    }

    @Test public void testDerivationPathCondition_isNotEffectFalse() {
        EdgeToNode edgeToNode =
                new EdgeToNode(new MergedEdge(() -> StatementOrBundle.Kind.PROV_DERIVATION, node2, node1), node2);

        DerivationPathCondition derivationPathCondition = new DerivationPathCondition(true);

        assert !derivationPathCondition.test(edgeToNode);
    }

}
