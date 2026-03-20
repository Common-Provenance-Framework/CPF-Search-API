package cz.muni.xmichalk.queryService;

import cz.muni.xmichalk.models.QueryParams;
import cz.muni.xmichalk.models.QueryResult;
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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.nio.file.AccessDeniedException;
import java.util.ArrayList;
import java.util.List;


@RestController
public class BundleQueryController {

    private static final Logger log = LoggerFactory.getLogger(BundleQueryController.class);
    private final BundleQueryService bundleQueryService;

    public BundleQueryController(BundleQueryService bundleQueryService) {
        this.bundleQueryService = bundleQueryService;
    }

    @Operation(
            summary = "Answer a given query about a given bundle",
            description = "Traverse the bundle from the specified node to answer the query. Can also use the metadata of the bundle to answer the query."
    ) @PostMapping(value = "/api/bundleQuery", produces = MediaType.APPLICATION_JSON_VALUE)
    @SecurityRequirement(name = "auth") @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Query Params", required = true, content = @Content(
            schema = @Schema(implementation = QueryParams.class), examples = {
            @ExampleObject(
                    name = "Get subgraph of Derivation/Specialization relations going backward from the start node",
                    value = """
                            {
                              "bundleId": {
                                "nameSpaceUri": "http://prov-storage-2:8000/api/v1/organizations/ORG2/documents/",
                                "localPart": "ProcessingBundle_V1"
                              },
                              "startNodeId": {
                                "nameSpaceUri": "https://openprovenance.org/blank/",
                                "localPart": "ProcessedSampleCon"
                              },
                              "querySpecification": {
                                 "type" : "GetSubgraphs",
                                 "fromSubgraphs" : {
                                   "type" : "DerivationPathFromStartNode",
                                   "backward" : true
                                }
                              }
                            }
                            """
            ), @ExampleObject(
            name = "Find a subgraph of Usage/Generation/Specialization relations going forward from the start node, Specialization going both directions",
            value = """
                    {
                      "bundleId": {
                        "nameSpaceUri": "http://prov-storage-2:8000/api/v1/organizations/ORG2/documents/",
                        "localPart": "ProcessingBundle_V0"
                      },
                      "startNodeId": {
                        "nameSpaceUri": "https://openprovenance.org/blank/",
                        "localPart": "StoredSampleCon_r1"
                      },
                      "querySpecification": {
                        "type" : "GetSubgraphs",
                        "fromSubgraphs" : {
                          "type" : "FilteredSubgraphs",
                          "filter" : {
                            "type" : "AnyTrue",
                            "conditions" : [ {
                              "type" : "EdgeToNodeCondition",
                              "edgeCondition" : {
                                "type" : "AnyTrue",
                                "conditions" : [ {
                                  "type" : "IsRelation",
                                  "relation" : "PROV_USAGE"
                                }, {
                                  "type" : "IsRelation",
                                  "relation" : "PROV_GENERATION"
                                } ]
                              },
                              "nodeIsEffect" : true
                            }, {
                              "type" : "EdgeToNodeCondition",
                              "edgeCondition" : {
                                "type" : "IsRelation",
                                "relation" : "PROV_SPECIALIZATION"
                              }
                            } ]
                          },
                          "startsIn" : {
                            "type" : "StartNode"
                          }
                        }
                      }
                    }
                    """
    ), @ExampleObject(
            name = "Get actions associated with Jane Smith", value = """
            {
              "bundleId": {
                "nameSpaceUri": "http://prov-storage-1:8000/api/v1/organizations/ORG1/documents/",
                "localPart": "SamplingBundle_V1"
              },
              "startNodeId": {
                "nameSpaceUri": "https://openprovenance.org/blank/",
                "localPart": "StoredSampleCon_r1"
              },
              "querySpecification": {
                "type" : "GetNodes",
                "fromSubgraphs" : {
                  "type" : "FittingNodes",
                  "nodeCondition" : {
                    "type" : "IsKind",
                    "kind" : "PROV_ACTIVITY"
                  },
                  "startsIn" : {
                    "type" : "FittingLinearSubgraphs",
                    "graphParts" : [ {
                      "type" : "EdgeToNodeCondition",
                      "nodeCondition" : {
                        "type" : "IsKind",
                        "kind" : "PROV_ACTIVITY"
                      }
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
            }
            """
    ), @ExampleObject(
            name = "Get main activity id", value = """
            {
              "bundleId": {
                "nameSpaceUri": "http://prov-storage-3:8000/api/v1/organizations/ORG3/documents/",
                "localPart": "SpeciesIdentificationBundle_V0"
              },
              "startNodeId": {
                "nameSpaceUri": "https://openprovenance.org/blank/",
                "localPart": "IdentifiedSpeciesCon"
              },
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
            name = "Get backward connectors that the start connector was derived from", value = """
            {
              "bundleId": {
                "nameSpaceUri": "http://prov-storage-3:8000/api/v1/organizations/ORG3/documents/",
                "localPart": "SpeciesIdentificationBundle_V0"
              },
              "startNodeId": {
                "nameSpaceUri": "https://openprovenance.org/blank/",
                "localPart": "IdentifiedSpeciesCon"
              },
              "querySpecification": {
                "type" : "GetConnectors",
                "backward" : true,
                "fromSubgraphs" : {
                  "type" : "DerivationPathFromStartNode",
                  "backward" : true
                }
              }
            }
            """
    ), @ExampleObject(
            name = "Test whether bundle has exactly one main activity", value = """
            {
              "bundleId": {
                "nameSpaceUri": "http://prov-storage-2:8000/api/v1/organizations/ORG2/documents/",
                "localPart": "ProcessingBundle_V0"
              },
              "startNodeId": {
                "nameSpaceUri": "https://openprovenance.org/blank/",
                "localPart": "StoredSampleCon_r1"
              },
              "querySpecification": {
                "type" : "TestBundleFits",
                "condition" : {
                  "type" : "CountComparisonCondition",
                  "first" : {
                    "type" : "FittingNodes",
                    "nodeCondition" : {
                      "type" : "HasAttrQualifiedNameValue",
                      "attributeNameUri" : "http://www.w3.org/ns/prov#type",
                      "valueUriRegex" : "https://www.commonprovenancemodel.org/cpm-namespace-v1-0/mainActivity"
                    }
                  },
                  "comparisonResult" : "EQUALS",
                  "second" : {
                    "type" : "CountConstant",
                    "count" : 1
                  }
                }
              }
            }
            """
    ), @ExampleObject(
            name = "Get bundle id of the newest version of this bundle", value = """
            {
              "bundleId": {
                "nameSpaceUri": "http://prov-storage-1:8000/api/v1/organizations/ORG1/documents/",
                "localPart": "SamplingBundle_V0"
              },
              "startNodeId": {
                "nameSpaceUri": "https://openprovenance.org/blank/",
                "localPart": "StoredSampleCon_r1"
              },
              "querySpecification": {
                "type" : "GetPreferredVersion",
                "versionPreference" : "LATEST"
              }
            }
            """
    )
    }
    )
    ) public ResponseEntity<?> bundleQuery(@RequestBody QueryParams queryParams, HttpServletRequest request) {

        List<String> missingParams = getMissingParams(queryParams);
        if (!missingParams.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(getMissingParamsMessage(missingParams));
        }

        String authorizationHeader = request.getHeader("Authorization");

        if (authorizationHeader == null || authorizationHeader.isBlank()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Missing Authorization header");
        }

        try {
            QualifiedName bundleId = queryParams.bundleId == null ? null : queryParams.bundleId.toQN();
            QualifiedName connectorId = queryParams.startNodeId == null ? null : queryParams.startNodeId.toQN();

            log.info(
                    "Received bundle query request for bundleId: {}, startNodeId: {}, query type: {}",
                    bundleId,
                    connectorId,
                    queryParams.querySpecification.getClass().getName()
            );

            QueryResult queryResult = bundleQueryService.evaluateBundleQuery(
                    bundleId,
                    connectorId,
                    queryParams.querySpecification,
                    authorizationHeader
            );

            log.info(
                    "Answering bundle query request for bundleId: {}, startNodeId: {}, query type: {}, with result: {}",
                    bundleId,
                    connectorId,
                    queryParams.querySpecification.getClass().getName(),
                    queryResult.result
            );
            return ResponseEntity.ok(queryResult);
        } catch (AccessDeniedException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(e.getMessage());
        } catch (Exception e) {
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

    private static List<String> getMissingParams(QueryParams params) {
        List<String> missing = new ArrayList<String>();
        if (params.bundleId == null) missing.add("bundleId");
        if (params.querySpecification == null) missing.add("querySpecification");

        return missing;
    }
}
