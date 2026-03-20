package cz.muni.xmichalk.dto;

import com.fasterxml.jackson.databind.JsonNode;
import cz.muni.xmichalk.models.ResultFromBundle;
import cz.muni.xmichalk.validity.EValidityCheck;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class FoundResultDTO {
    public QualifiedNameDTO bundleId;
    public QualifiedNameDTO fromConnectorId;
    public boolean integrity;
    public List<Map.Entry<EValidityCheck, Boolean>> validityChecks;
    public boolean pathIntegrity;
    public List<Map.Entry<EValidityCheck, Boolean>> pathValidityChecks;
    public JsonNode result;


    public FoundResultDTO() {

    }

    public FoundResultDTO(
            QualifiedNameDTO bundleId,
            QualifiedNameDTO fromConnectorId,
            boolean integrity,
            List<Map.Entry<EValidityCheck, Boolean>> validityChecks,
            boolean pathIntegrity,
            List<Map.Entry<EValidityCheck, Boolean>> pathValidityChecks,
            JsonNode result
    ) {
        this.bundleId = bundleId;
        this.fromConnectorId = fromConnectorId;
        this.integrity = integrity;
        this.validityChecks = validityChecks;
        this.pathIntegrity = pathIntegrity;
        this.pathValidityChecks = pathValidityChecks;
        this.result = result;
    }

    public FoundResultDTO from(ResultFromBundle domainModel) {
        if (domainModel == null) {
            return null;
        }
        this.bundleId = new QualifiedNameDTO().from(domainModel.bundleId);
        this.fromConnectorId = new QualifiedNameDTO().from(domainModel.fromConnectorId);
        this.result = domainModel.result;
        this.integrity = domainModel.integrity;
        this.validityChecks = new ArrayList<>(domainModel.validityChecks);
        this.pathIntegrity = domainModel.pathIntegrity;
        this.pathValidityChecks = new ArrayList<>(domainModel.pathValidityChecks);
        return this;
    }
}
