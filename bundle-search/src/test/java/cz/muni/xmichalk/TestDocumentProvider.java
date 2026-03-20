package cz.muni.xmichalk;

import cz.muni.fi.cpm.merged.CpmMergedFactory;
import cz.muni.fi.cpm.model.CpmDocument;
import cz.muni.fi.cpm.model.ICpmFactory;
import cz.muni.fi.cpm.model.ICpmProvFactory;
import cz.muni.fi.cpm.template.mapper.ITemplateProvMapper;
import cz.muni.fi.cpm.template.mapper.TemplateProvMapper;
import cz.muni.fi.cpm.template.schema.*;
import cz.muni.fi.cpm.vanilla.CpmProvFactory;
import org.openprovenance.prov.model.*;
import org.openprovenance.prov.model.interop.Formats;
import org.openprovenance.prov.vanilla.ProvFactory;

import javax.xml.datatype.DatatypeFactory;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static cz.muni.xmichalk.util.NameSpaceConstants.BLANK_URI;
import static cz.muni.xmichalk.util.ProvDocumentUtils.deserializeFile;

public class TestDocumentProvider {
    private static final ProvFactory pF = new ProvFactory();
    private static final ICpmFactory cF = new CpmMergedFactory(pF);
    private static final ICpmProvFactory cPF = new CpmProvFactory(pF);
    private static final String dataFolder = System.getProperty("user.dir") + "/src/test/resources/data/";

    public static CpmDocument testDocument1 = getTestDocument1();
    public static CpmDocument testDocument2 = getTestDocument2();

    public static CpmDocument samplingBundle_V0 = loadCpmDocument(dataFolder + "dataset1/SamplingBundle_V0.json");
    public static CpmDocument samplingBundle_V1 = loadCpmDocument(dataFolder + "dataset1/SamplingBundle_V1.json");
    public static CpmDocument processingBundle_V0 = loadCpmDocument(dataFolder + "dataset2/ProcessingBundle_V0.json");
    public static CpmDocument processingBundle_V1 = loadCpmDocument(dataFolder + "dataset2/ProcessingBundle_V1.json");
    public static CpmDocument speciesIdentificationBundle_V0 =
            loadCpmDocument(dataFolder + "dataset3/SpeciesIdentificationBundle_V0.json");
    public static CpmDocument dnaSequencingBundle_V0 =
            loadCpmDocument(dataFolder + "dataset4/DnaSequencingBundle_V0.json");

    public static CpmDocument samplingBundle_V0_meta = loadCpmDocument(dataFolder + "SamplingBundle_V0_meta.json");
    public static CpmDocument processingBundle_V0_meta = loadCpmDocument(dataFolder + "ProcessingBundle_V0_meta.json");
    public static CpmDocument speciesIdentificationBundle_V0_meta =
            loadCpmDocument(dataFolder + "SpeciesIdentificationBundle_V0_meta.json");
    public static CpmDocument dnaSequencingBundle_V0_meta =
            loadCpmDocument(dataFolder + "DnaSequencingBundle_V0_meta.json");

    public static CpmDocument getTestDocument1() {
        QualifiedName entityId = new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "entity1", "blank");
        Entity entity = cPF.getProvFactory().newEntity(entityId);

        QualifiedName agentId = new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "agent1", "blank");
        Agent agent = cPF.getProvFactory().newAgent(agentId);

        QualifiedName activityId = new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "activity1", "blank");
        Activity activity = cPF.getProvFactory().newActivity(activityId);
        activity.setStartTime(pF.newISOTime("2025-08-16T10:00:00Z"));
        activity.setEndTime(pF.newISOTime("2025-08-16T11:00:00Z"));

        Relation relation = cPF.getProvFactory()
                .newWasAttributedTo(
                        new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "attr", "blank"),
                        entityId,
                        agentId
                );
        Relation relation2 = cPF.getProvFactory()
                .newWasAssociatedWith(
                        new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "assoc", "blank"),
                        activityId,
                        agentId
                );
        Relation relation3 = cPF.getProvFactory()
                .newWasGeneratedBy(
                        new org.openprovenance.prov.vanilla.QualifiedName(BLANK_URI, "gen", "blank"),
                        entityId,
                        activityId
                );

        QualifiedName bundleId = pF.newQualifiedName("www.example.com/", "bundleA", "ex");

        return new CpmDocument(List.of(entity, agent, activity, relation, relation2, relation3), bundleId, pF, cPF, cF);
    }

    public static CpmDocument getTestDocument2() {
        try {
            DatatypeFactory datatypeFactory = DatatypeFactory.newInstance();
            TraversalInformation ti = new TraversalInformation();

            ti.setPrefixes(Map.of("ex", "www.example.com/"));
            ti.setBundleName(ti.getNamespace().qualifiedName("ex", "bundleB", pF));

            MainActivity mA = new MainActivity(ti.getNamespace().qualifiedName("ex", "activity1", pF));
            mA.setStartTime(datatypeFactory.newXMLGregorianCalendar("2011-11-16T16:05:00"));
            mA.setEndTime(datatypeFactory.newXMLGregorianCalendar("2011-11-16T18:05:00"));
            ti.setMainActivity(mA);

            QualifiedName bcID = ti.getNamespace().qualifiedName("ex", "backConnector1", pF);
            BackwardConnector bC = new BackwardConnector(bcID);
            ti.getBackwardConnectors().add(bC);

            MainActivityUsed used = new MainActivityUsed(bcID);
            mA.setUsed(List.of(used));

            QualifiedName fcID = ti.getNamespace().qualifiedName("ex", "forwardConnector1", pF);
            mA.setGenerated(List.of(fcID));

            ForwardConnector fC = new ForwardConnector(fcID);
            fC.setDerivedFrom(List.of(bC.getId()));
            ti.getForwardConnectors().add(fC);

            ITemplateProvMapper mapper = new TemplateProvMapper(new CpmProvFactory(pF));
            Document document = mapper.map(ti);
            return new CpmDocument(document, pF, cPF, cF);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static CpmDocument loadCpmDocument(String filePath) {
        try {
            Document document = deserializeFile(Path.of(filePath), Formats.ProvFormat.JSON);
            return new CpmDocument(document, pF, cPF, cF);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
