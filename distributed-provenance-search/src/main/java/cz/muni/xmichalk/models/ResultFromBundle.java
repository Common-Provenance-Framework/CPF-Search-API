package cz.muni.xmichalk.models;

import com.fasterxml.jackson.databind.JsonNode;
import cz.muni.xmichalk.validity.EValidityCheck;
import org.openprovenance.prov.model.QualifiedName;

import java.util.List;
import java.util.Map;

public class ResultFromBundle {
    public QualifiedName bundleId;
    public QualifiedName fromConnectorId;
    public JsonNode result;
    public boolean integrity;
    public List<Map.Entry<EValidityCheck, Boolean>> validityChecks;
    public boolean pathIntegrity;
    public List<Map.Entry<EValidityCheck, Boolean>> pathValidityChecks;


    public ResultFromBundle() {

    }

    public ResultFromBundle(
            QualifiedName bundleId,
            QualifiedName fromConnectorId,
            JsonNode result,
            boolean integrity,
            List<Map.Entry<EValidityCheck, Boolean>> validityChecks,
            boolean pathIntegrity,
            List<Map.Entry<EValidityCheck, Boolean>> pathValidityChecks
    ) {
        this.bundleId = bundleId;
        this.fromConnectorId = fromConnectorId;
        this.result = result;
        this.integrity = integrity;
        this.validityChecks = validityChecks;
        this.pathIntegrity = pathIntegrity;
        this.pathValidityChecks = pathValidityChecks;
    }
}
