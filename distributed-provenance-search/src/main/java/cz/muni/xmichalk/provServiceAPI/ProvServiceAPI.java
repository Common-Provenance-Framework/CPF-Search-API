package cz.muni.xmichalk.provServiceAPI;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import cz.muni.xmichalk.dto.BundleQueryDTO;
import cz.muni.xmichalk.dto.BundleQueryResultDTO;
import cz.muni.xmichalk.dto.QualifiedNameDTO;
import org.openprovenance.prov.model.QualifiedName;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;

public class ProvServiceAPI implements IProvServiceAPI {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public BundleQueryResultDTO fetchBundleQueryResult(
            String serviceUri,
            QualifiedName bundleId,
            QualifiedName connectorId,
            String authorizationHeader,
            JsonNode querySpecification
    ) {
        BundleQueryDTO queryParams = new BundleQueryDTO(bundleId, connectorId, querySpecification);

        if (serviceUri == null) {
            throw new IllegalArgumentException("Prov service cannot be null.");
        }

        String url = serviceUri + "bundleQuery";

        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", authorizationHeader);

        HttpEntity<BundleQueryDTO> request = new HttpEntity<>(queryParams, headers);

        ResponseEntity<BundleQueryResultDTO> response =
                restTemplate.postForEntity(url, request, BundleQueryResultDTO.class);

        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new RuntimeException("Bundle query API call failed with status: " + response.getStatusCode());
        }

        return response.getBody();
    }

    public QualifiedName fetchPreferredBundleVersion(
            String serviceUri,
            QualifiedName bundleId,
            QualifiedName metaId,
            String authorizationHeader,
            String versionPreference
    ) {
        String metaUri = (metaId != null) ? "\"" + metaId.getUri() + "\"" : null;
        JsonNode query = null;
        try {
            query = objectMapper.readTree("""
                                                      {
                                                        "type": "GetPreferredVersion",
                                                        "versionPreference": "%s",
                                                        "metaUri": %s
                                                      }
                                                  """.formatted(versionPreference, metaUri));
        } catch (IOException e) {
            throw new RuntimeException("Failed to create GetPreferredVersion query JSON.", e);
        }


        BundleQueryResultDTO queryResult =
                fetchBundleQueryResult(serviceUri, bundleId, null, authorizationHeader, query);

        if (queryResult == null || queryResult.result == null) {
            return null;
        }

        QualifiedNameDTO pickedBundleIdDto = objectMapper.convertValue(
                queryResult.result, new TypeReference<QualifiedNameDTO>() {
                }
        );

        return pickedBundleIdDto == null ? null : pickedBundleIdDto.toQN();
    }

    public BundleQueryResultDTO fetchBundleConnectors(
            String serviceUri,
            QualifiedName bundleId,
            QualifiedName connectorId,
            String authorizationHeader,
            boolean backward
    ) {
        JsonNode query = null;
        try {
            query = objectMapper.readTree("""
                                                      {
                                                        "type": "GetConnectors",
                                                        "backward": %s,
                                                        "fromSubgraphs" : {
                                                          "type" : "DerivationPathFromStartNode",
                                                          "backward" : %s
                                                        }
                                                      }
                                                  """.formatted(backward, backward));
        } catch (IOException e) {
            throw new RuntimeException("Failed to create GetConnectors query JSON.", e);
        }

        return fetchBundleQueryResult(serviceUri, bundleId, connectorId, authorizationHeader, query);
    }
}
