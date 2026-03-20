package cz.muni.xmichalk.models;

import com.fasterxml.jackson.databind.JsonNode;
import cz.muni.xmichalk.traversalPriority.ETraversalPriority;
import cz.muni.xmichalk.validity.EValidityCheck;

import java.util.List;

public class TraversalParams {
    public boolean traverseBackwards;
    public String authorizationHeader;
    public String versionPreference;
    public ETraversalPriority traversalPriority;
    public List<EValidityCheck> validityChecks;
    public JsonNode querySpecification;

    public TraversalParams() {

    }

    public TraversalParams(
            boolean traverseBackwards,
            String authorizationHeader,
            String versionPreference,
            ETraversalPriority traversalPriority,
            List<EValidityCheck> validityChecks,
            JsonNode querySpecification
    ) {
        this.traverseBackwards = traverseBackwards;
        this.authorizationHeader = authorizationHeader;
        this.versionPreference = versionPreference;
        this.traversalPriority = traversalPriority;
        this.validityChecks = validityChecks;
        this.querySpecification = querySpecification;
    }
}
