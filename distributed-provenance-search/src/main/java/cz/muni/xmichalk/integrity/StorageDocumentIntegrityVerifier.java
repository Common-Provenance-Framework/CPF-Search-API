package cz.muni.xmichalk.integrity;

import com.fasterxml.jackson.databind.ObjectMapper;
import cz.muni.xmichalk.dto.token.Token;
import org.erdtman.jcs.JsonCanonicalizer;
import org.openprovenance.prov.model.QualifiedName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

public class StorageDocumentIntegrityVerifier implements IIntegrityVerifier {
    private static final Logger log = LoggerFactory.getLogger(StorageDocumentIntegrityVerifier.class);

    public boolean verifyIntegrity(QualifiedName document, Token token) {
        return verifySignature(token) && verifyTokenExists(document, token);
    }

    public boolean verifySignature(Token token) {
        try {
            PublicKey publicKey = loadPublicKeyFromCertificate(token.data().additionalData().trustedPartyCertificate());

            ObjectMapper mapper = new ObjectMapper();
            String tokenDataJsonString = mapper.writeValueAsString(token.data());
            byte[] canonized = new JsonCanonicalizer(tokenDataJsonString).getEncodedUTF8();

            byte[] signatureBytes = Base64.getDecoder().decode(token.signature());

            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(publicKey);
            verifier.update(canonized);
            return verifier.verify(signatureBytes);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public boolean verifyTokenExists(QualifiedName document, Token token) {
        String trustedPartyUri = token.data().additionalData().trustedPartyUri();
        String url = trustedPartyUri + "/api/v1/organizations/" + token.data().originatorId() + "/tokens";
        if (!url.startsWith("http")) {
            url = "http://" + url;
        }

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<List<Token>> response = restTemplate.exchange(
                url, HttpMethod.GET, null, new ParameterizedTypeReference<List<Token>>() {
                }
        );

        if (!response.getStatusCode().is2xxSuccessful()) {
            log.error("Get document token API call failed with status: {}", response.getStatusCode());
            return false;
        }

        if (response.getBody() == null) {
            return false;
        }

        return response.getBody().contains(token);

    }

    public PublicKey loadPublicKeyFromCertificate(String pemCert) throws Exception {
        ByteArrayInputStream certStream = new ByteArrayInputStream(pemCert.getBytes(StandardCharsets.UTF_8));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(certStream);
        return cert.getPublicKey();
    }

    public boolean verifyHash(String data, String hashFunctionName, String expectedHexHash) {
        MessageDigest hashFunction = getHashFunction(hashFunctionName);
        byte[] hash = hashString(data, hashFunction);
        String hashHex = bytesToHex(hash);
        return hashHex.equals(expectedHexHash);
    }

    public MessageDigest getHashFunction(String hashFunction) {
        try {
            return MessageDigest.getInstance(hashFunction);
        } catch (Exception e) {
            throw new RuntimeException("Unsupported hash function: " + hashFunction, e);
        }
    }

    public byte[] hashString(String input, MessageDigest digest) {
        byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
        digest.update(inputBytes);
        return digest.digest();
    }

    public String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
