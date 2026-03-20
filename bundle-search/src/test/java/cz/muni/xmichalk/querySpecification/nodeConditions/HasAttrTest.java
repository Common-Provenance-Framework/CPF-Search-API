package cz.muni.xmichalk.querySpecification.nodeConditions;

import cz.muni.fi.cpm.merged.CpmMergedFactory;
import cz.muni.fi.cpm.merged.MergedNode;
import cz.muni.fi.cpm.model.ICpmFactory;
import cz.muni.fi.cpm.model.ICpmProvFactory;
import cz.muni.fi.cpm.model.INode;
import cz.muni.fi.cpm.vanilla.CpmProvFactory;
import cz.muni.xmichalk.models.QualifiedNameData;
import org.junit.jupiter.api.Test;
import org.openprovenance.prov.model.Entity;
import org.openprovenance.prov.model.QualifiedName;
import org.openprovenance.prov.vanilla.Other;
import org.openprovenance.prov.vanilla.ProvFactory;

import java.util.List;

import static cz.muni.xmichalk.util.NameSpaceConstants.BLANK_URI;
import static cz.muni.xmichalk.util.NameSpaceConstants.PROV_URI;

public class HasAttrTest {
    ProvFactory pF = new ProvFactory();
    ICpmFactory cF = new CpmMergedFactory(pF);
    ICpmProvFactory cPF = new CpmProvFactory(pF);

    @Test public void testHasAttr_true() {
        QualifiedName entityId = new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "entity1", "blank");
        Entity entity = new org.openprovenance.prov.vanilla.Entity(
                entityId, List.of(new Other(
                new QualifiedNameData("attr/", "Name").toQN(),
                new QualifiedNameData(PROV_URI, "QUALIFIED_NAME").toQN(),
                new QualifiedNameData("attr/", "Value").toQN()

        ))
        );
        INode node = new MergedNode(entity);

        HasAttr hasAttrCondition = new HasAttr("attr/Name");

        assert hasAttrCondition.test(node);
    }

    @Test public void testHasAttr_false() {
        QualifiedName entityId = new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "entity1", "blank");
        Entity entity = new org.openprovenance.prov.vanilla.Entity(
                entityId, List.of(new Other(
                new QualifiedNameData("attr/", "Name").toQN(),
                new QualifiedNameData(PROV_URI, "QUALIFIED_NAME").toQN(),
                new QualifiedNameData("attr/", "Value").toQN()

        ))
        );
        INode node = new MergedNode(entity);

        HasAttr hasAttrCondition = new HasAttr("other/Name");

        assert !hasAttrCondition.test(node);
    }
}
