package cz.muni.xmichalk;

import com.fasterxml.jackson.databind.JsonNode;
import cz.muni.xmichalk.dto.ConnectorDTO;
import org.openprovenance.prov.model.QualifiedName;

import java.util.List;

public class TestBundleData {
    public QualifiedName id;
    public QualifiedName latestVersionId;
    public JsonNode queryResult;
    public List<ConnectorDTO> forwardConnectors;
    public List<ConnectorDTO> backwardConnectors;

    public TestBundleData(
            QualifiedName id,
            QualifiedName latestVersionId,
            JsonNode queryResult,
            List<ConnectorDTO> backwardConnectors,
            List<ConnectorDTO> forwardConnectors
    ) {
        this.id = id;
        this.latestVersionId = latestVersionId;
        this.queryResult = queryResult;
        this.backwardConnectors = backwardConnectors;
        this.forwardConnectors = forwardConnectors;
    }
}
