package cz.muni.xmichalk;

import cz.muni.fi.cpm.merged.CpmMergedFactory;
import cz.muni.fi.cpm.model.CpmDocument;
import cz.muni.fi.cpm.model.ICpmFactory;
import cz.muni.fi.cpm.model.ICpmProvFactory;
import cz.muni.fi.cpm.vanilla.CpmProvFactory;
import cz.muni.xmichalk.storage.EBundlePart;
import cz.muni.xmichalk.storage.IStorage;
import cz.muni.xmichalk.storage.StorageCpmDocument;
import cz.muni.xmichalk.util.ProvDocumentUtils;
import org.openprovenance.prov.model.Document;
import org.openprovenance.prov.model.interop.Formats;
import org.openprovenance.prov.vanilla.ProvFactory;

import java.nio.file.Path;

public class MockedStorage implements IStorage {
    ProvFactory pF = new ProvFactory();
    ICpmFactory cF = new CpmMergedFactory(pF);
    ICpmProvFactory cPF = new CpmProvFactory(pF);
    String dataFolder = System.getProperty("user.dir") + "/src/test/resources/data/";

    public static String authTokenFullAccess = "full_access_token";
    public static String authTokenNoAccess = "no_access_token";
    public static String authTokenExcludeBundleIdPrefix = "Exclude ";

    @Override
    public StorageCpmDocument loadCpmDocument(final String uri, EBundlePart part, String authorizationHeader) {
        Document document = getFromFile(uri);
        return new StorageCpmDocument(new CpmDocument(document, pF, cPF, cF), null);
    }

    @Override public StorageCpmDocument loadMetaCpmDocument(final String uri, String authorizationHeader) {
        Document document = getFromFile(uri);
        return new StorageCpmDocument(new CpmDocument(document, pF, cPF, cF), null);
    }

    private Document getFromFile(String uri) {
        String localName = uri.substring(uri.lastIndexOf('/') + 1);

        String filePath = null;

        try {
            switch (localName) {
                case "SamplingBundle_V0" -> {
                    filePath = dataFolder + "dataset1/SamplingBundle_V0.json";
                }
                case "SamplingBundle_V1" -> {
                    filePath = dataFolder + "dataset1/SamplingBundle_V1.json";
                }
                case "ProcessingBundle_V0" -> {
                    filePath = dataFolder + "dataset2/ProcessingBundle_V0.json";
                }
                case "ProcessingBundle_V1" -> {
                    filePath = dataFolder + "dataset2/ProcessingBundle_V1.json";
                }
                case "SpeciesIdentificationBundle_V0" -> {
                    filePath = dataFolder + "dataset3/SpeciesIdentificationBundle_V0.json";
                }
                case "DnaSequencingBundle_V0" -> {
                    filePath = dataFolder + "dataset4/DnaSequencingBundle_V0.json";
                }
                case "SamplingBundle_V0_meta" -> {
                    filePath = dataFolder + "SamplingBundle_V0_meta.json";
                }
                case "ProcessingBundle_V0_meta" -> {
                    filePath = dataFolder + "ProcessingBundle_V0_meta.json";
                }
                case "SpeciesIdentificationBundle_V0_meta" -> {
                    filePath = dataFolder + "SpeciesIdentificationBundle_V0_meta.json";
                }
                case "DnaSequencingBundle_V0_meta" -> {
                    filePath = dataFolder + "DnaSequencingBundle_V0_meta.json";
                }
                default -> throw new RuntimeException("Unknown document URI: " + uri);
            }

            return ProvDocumentUtils.deserializeFile(Path.of(filePath), Formats.ProvFormat.JSON);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }
}
