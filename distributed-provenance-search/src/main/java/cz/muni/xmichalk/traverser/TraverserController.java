package cz.muni.xmichalk.traverser;


import cz.muni.xmichalk.dto.FoundResultDTO;
import cz.muni.xmichalk.dto.TraversalParamsDTO;
import cz.muni.xmichalk.dto.TraversalResultsDTO;
import cz.muni.xmichalk.models.TraversalParams;
import cz.muni.xmichalk.models.TraversalResults;
import cz.muni.xmichalk.traversalPriority.ETraversalPriority;
import cz.muni.xmichalk.validity.EValidityCheck;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.servlet.http.HttpServletRequest;
import org.openprovenance.prov.model.QualifiedName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@RestController
public class TraverserController {
    private static final Logger log = LoggerFactory.getLogger(TraverserController.class);
    private final Traverser traverser;

    public TraverserController(Traverser traverser) {
        this.traverser = traverser;
    }

    @Operation(summary = "List available validity checks", description = "Returns all defined validity checks.")
    @GetMapping(value = "/api/getValidityChecks", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Set<EValidityCheck>> getAvailableValidityChecks() {
        Set<EValidityCheck> checks = traverser.getValidityVerifiers().keySet();

        return ResponseEntity.ok(checks);
    }

    @Operation(
            summary = "List available traversal priority options",
            description = "Returns all defined traversal priority options."
    ) @GetMapping(value = "/api/getTraversalPriorities", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Set<ETraversalPriority>> getAvailableTraversalPriorities() {
        Set<ETraversalPriority> options = traverser.getTraversalPriorityComparators().keySet();

        return ResponseEntity.ok(options);
    }

    @Operation(summary = "Traverses given bundle and its predecessors to find results for the query.")
    @PostMapping(value = "/api/traversePredecessors", produces = MediaType.APPLICATION_JSON_VALUE)
    @SecurityRequirement(name = "auth") @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Traversal Params", required = true, content = @Content(
            schema = @Schema(implementation = TraversalParamsDTO.class), examples = {
            @ExampleObject(
                    name = "Get storing activities on the usage/generation path going backwards (via undirected Specializations, backward Generations and Usages)",
                    value = """
                            {
                              "bundleId": {
                                "nameSpaceUri": "http://prov-storage-4:8000/api/v1/organizations/ORG4/documents/",
                                "localPart": "DnaSequencingBundle_V0"
                              },
                              "startNodeId": {
                                "nameSpaceUri": "https://openprovenance.org/blank/",
                                "localPart": "FilteredSequencesCon"
                              },
                              "versionPreference": "SPECIFIED",
                              "traversalPriority": "INTEGRITY_THEN_ORDERED_VALIDITY_CHECKS",
                              "validityChecks": ["DEMO_SIMPLE_CONSTRAINTS"],
                              "querySpecification": {
                                "type": "GetNodes",
                                "fromSubgraphs": {
                                  "type": "FittingNodes",
                                  "nodeCondition": {
                                    "type": "AllTrue",
                                    "conditions": [
                                      {
                                        "type": "IsKind",
                                        "kind": "PROV_ACTIVITY"
                                      },
                                      {
                                        "type": "HasAttrLangStringValue",
                                        "attributeNameUri": "http://purl.org/dc/terms/type",
                                        "valueRegex": "(?i).*storing.*"
                                      }
                                    ]
                                  },
                                  "startsIn": {
                                    "type": "FilteredSubgraphs",
                                    "filter": {
                                      "type": "AnyTrue",
                                      "conditions": [
                                        {
                                          "type": "EdgeToNodeCondition",
                                          "edgeCondition": {
                                            "type": "AnyTrue",
                                            "conditions": [
                                              {
                                                "type": "IsRelation",
                                                "relation": "PROV_USAGE"
                                              },
                                              {
                                                "type": "IsRelation",
                                                "relation": "PROV_GENERATION"
                                              }
                                            ]
                                          },
                                          "nodeIsEffect": false
                                        },
                                        {
                                          "type": "EdgeToNodeCondition",
                                          "edgeCondition": {
                                            "type": "IsRelation",
                                            "relation": "PROV_SPECIALIZATION"
                                          }
                                        }
                                      ]
                                    },
                                    "startsIn": {
                                      "type": "StartNode"
                                    }
                                  }
                                }
                              }
                            }
                            """
            ), @ExampleObject(
            name = "Get all backward connectors", value = """
            {
              "bundleId": {
                "nameSpaceUri": "http://prov-storage-3:8000/api/v1/organizations/ORG3/documents/",
                "localPart": "SpeciesIdentificationBundle_V0"
              },
              "startNodeId": {
                "nameSpaceUri": "https://openprovenance.org/blank/",
                "localPart": "IdentifiedSpeciesCon"
              },
              "versionPreference": "SPECIFIED",
              "traversalPriority": "INTEGRITY_THEN_ORDERED_VALIDITY_CHECKS",
              "validityChecks": ["DEMO_SIMPLE_CONSTRAINTS"],
              "querySpecification": {
                "type": "GetConnectors",
                "backward": "true"
              }
            }
            """
    ),

    }
    )
    ) public ResponseEntity<?> traversePredecessors(
            @RequestBody TraversalParamsDTO traverseParams,
            HttpServletRequest request
    ) {
        String authorizationHeader = request.getHeader("Authorization");
        return traverseChain(traverseParams, true, authorizationHeader);
    }

    @Operation(summary = "Traverses given bundle and its successors to find results for the query.")
    @PostMapping(value = "/api/traverseSuccessors", produces = MediaType.APPLICATION_JSON_VALUE)
    @SecurityRequirement(name = "auth") @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Traversal Params", required = true, content = @Content(
            schema = @Schema(implementation = TraversalParamsDTO.class), examples = {
            @ExampleObject(
                    name = "Get main activity ids", value = """
                    {
                      "bundleId": {
                        "nameSpaceUri": "http://prov-storage-1:8000/api/v1/organizations/ORG1/documents/",
                        "localPart": "SamplingBundle_V0"
                      },
                      "startNodeId": {
                        "nameSpaceUri": "https://openprovenance.org/blank/",
                        "localPart": "StoredSampleCon_r1"
                      },
                      "versionPreference": "LATEST",
                      "traversalPriority": "INTEGRITY_THEN_ORDERED_VALIDITY_CHECKS",
                      "validityChecks": ["DEMO_SIMPLE_CONSTRAINTS"],
                      "querySpecification": {
                         "type" : "GetNodeIds",
                         "fromSubgraphs" : {
                           "type" : "FittingNodes",
                           "nodeCondition" : {
                             "type" : "HasAttrQualifiedNameValue",
                             "attributeNameUri" : "http://www.w3.org/ns/prov#type",
                             "valueUriRegex" : "https://www.commonprovenancemodel.org/cpm-namespace-v1-0/mainActivity"
                           }
                         }
                       }
                    }
                    """
            ), @ExampleObject(
            name = "Find subgraphs of Jane Smith and activities they were responsible for", value = """
            {
              "bundleId": {
                "nameSpaceUri": "http://prov-storage-1:8000/api/v1/organizations/ORG1/documents/",
                "localPart": "SamplingBundle_V0"
              },
              "startNodeId": {
                "nameSpaceUri": "https://openprovenance.org/blank/",
                "localPart": "StoredSampleCon_r2_3um"
              },
              "versionPreference": "LATEST",
              "traversalPriority": "INTEGRITY_THEN_ORDERED_VALIDITY_CHECKS",
              "validityChecks": ["DEMO_SIMPLE_CONSTRAINTS"],
              "querySpecification": {
                "type" : "GetSubgraphs",
                "fromSubgraphs" : {
                  "type" : "FittingLinearSubgraphs",
                  "graphParts" : [ {
                    "type" : "EdgeToNodeCondition",
                    "edgeCondition" : null,
                    "nodeCondition" : {
                      "type" : "IsKind",
                      "kind" : "PROV_ACTIVITY"
                    },
                    "nodeIsEffect" : null
                  }, {
                    "type" : "EdgeToNodeCondition",
                    "edgeCondition" : {
                      "type" : "IsRelation",
                      "relation" : "PROV_ASSOCIATION"
                    },
                    "nodeCondition" : {
                      "type" : "AllTrue",
                      "conditions" : [ {
                        "type" : "HasAttrQualifiedNameValue",
                        "attributeNameUri" : "http://www.w3.org/ns/prov#type",
                        "valueUriRegex" : "https://schema.org/Person"
                      }, {
                        "type" : "HasAttrLangStringValue",
                        "attributeNameUri" : "https://schema.org/name",
                        "langRegex" : null,
                        "valueRegex" : "Jane Smith"
                      } ]
                    },
                    "nodeIsEffect" : false
                  } ],
                  "startsIn" : {
                    "type" : "WholeGraph"
                  }
                }
              }
            }
            """
    )
    }
    )
    ) public ResponseEntity<?> traverseSuccessors(
            @RequestBody TraversalParamsDTO traversalParams,
            HttpServletRequest request
    ) {
        String authorizationHeader = request.getHeader("Authorization");
        return traverseChain(traversalParams, false, authorizationHeader);
    }

    private ResponseEntity<?> traverseChain(
            TraversalParamsDTO traversalParams,
            boolean traverseBackwards,
            String authorizationHeader
    ) {
        List<String> missingParams = getMissingParams(traversalParams);
        if (!missingParams.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(getMissingParamsMessage(missingParams));
        }

        if (authorizationHeader == null || authorizationHeader.isBlank()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Missing Authorization header");
        }

        try {

            QualifiedName bundleId = traversalParams.bundleId.toQN();
            QualifiedName connectorId = traversalParams.startNodeId.toQN();

            TraversalResults results = traverser.traverseChain(
                    bundleId, connectorId, new TraversalParams(
                            traverseBackwards,
                            authorizationHeader,
                            traversalParams.versionPreference,
                            traversalParams.traversalPriority != null ?
                                    traversalParams.traversalPriority :
                                    ETraversalPriority.INTEGRITY_THEN_ORDERED_VALIDITY_CHECKS,
                            traversalParams.validityChecks != null ? traversalParams.validityChecks : new ArrayList<>(),
                            traversalParams.querySpecification
                    )
            );

            TraversalResultsDTO resultsDTO =
                    new TraversalResultsDTO(
                            results.results.stream().map(fr -> new FoundResultDTO().from(fr)).toList(),
                            results.errors
                    );

            return ResponseEntity.ok(resultsDTO);

        } catch (Exception e) {
            log.error("API traverseChain call failed: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    private static String getMissingParamsMessage(List<String> missingParams) {
        StringBuilder builder = new StringBuilder("Missing required fields in the request body: ");
        for (int i = 0; i < missingParams.size(); i++) {
            builder.append(missingParams.get(i));
            if (i < missingParams.size() - 1) {
                builder.append(", ");
            }
        }
        builder.append(".");
        return builder.toString();
    }

    private static List<String> getMissingParams(TraversalParamsDTO params) {
        List<String> missing = new ArrayList<String>();
        if (params.bundleId == null) missing.add("bundleId");
        if (params.startNodeId == null) missing.add("startNodeId");
        if (params.querySpecification == null) missing.add("querySpecification");

        return missing;
    }
}