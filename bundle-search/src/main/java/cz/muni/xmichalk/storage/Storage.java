package cz.muni.xmichalk.storage;

import com.fasterxml.jackson.databind.ObjectMapper;
import cz.muni.fi.cpm.model.CpmDocument;
import cz.muni.fi.cpm.model.ICpmFactory;
import cz.muni.fi.cpm.model.ICpmProvFactory;
import cz.muni.xmichalk.storage.storageDTO.GetDocumentResponse;
import cz.muni.xmichalk.storage.storageDTO.GetMetaResponse;
import cz.muni.xmichalk.util.ProvDocumentUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.openprovenance.prov.model.Document;
import org.openprovenance.prov.model.ProvFactory;
import org.openprovenance.prov.model.interop.Formats;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Storage implements IStorage {
    private static final Formats.ProvFormat FORMAT = Formats.ProvFormat.JSON;
    private static final String FORMAT_QUERY_PARAM = "format=json";
    private static final Charset CHARSET = StandardCharsets.UTF_8;
    private final ProvFactory provFactory;
    private final ICpmFactory cpmFactory;
    private final ICpmProvFactory cpmProvFactory;

    public Storage(ProvFactory provFactory, ICpmFactory cpmFactory, ICpmProvFactory cpmProvFactory) {
        this.provFactory = provFactory;
        this.cpmFactory = cpmFactory;
        this.cpmProvFactory = cpmProvFactory;
    }


    public StorageDocument loadDocument(String uri, String authorizationHeader) {
        try {
            uri += (uri.contains("?") ? "&" : "?") + FORMAT_QUERY_PARAM;
            String responseBody = getRequest(uri, authorizationHeader);
            ObjectMapper mapper = new ObjectMapper();
            GetDocumentResponse storageResponse = mapper.readValue(responseBody, GetDocumentResponse.class);
            String decodedDocument = decodeData(storageResponse.document);
            Document document = ProvDocumentUtils.deserialize(decodedDocument, FORMAT);
            return new StorageDocument(document, storageResponse.token);
        } catch (IOException e) {
            throw new RuntimeException("Failed to load document " + uri, e);
        }
    }

    @Override public StorageCpmDocument loadCpmDocument(String uri, EBundlePart part, String authorizationHeader) {
        if (part == EBundlePart.DomainSpecific) uri += "/domain-specific";
        else if (part == EBundlePart.TraversalInformation) uri += "/backbone";
        return toCpmDocument(loadDocument(uri, authorizationHeader));
    }

    public StorageDocument loadMetaDocument(String uri, String authorizationHeader) {
        try {
            uri += (uri.contains("?") ? "&" : "?") + FORMAT_QUERY_PARAM;
            String responseBody = getRequest(uri, authorizationHeader);
            ObjectMapper mapper = new ObjectMapper();
            GetMetaResponse storageResponse = mapper.readValue(responseBody, GetMetaResponse.class);
            String decodedDocument = decodeData(storageResponse.graph);
            Document document = ProvDocumentUtils.deserialize(decodedDocument, FORMAT);
            return new StorageDocument(document, storageResponse.token);
        } catch (IOException e) {
            throw new RuntimeException("Failed to load document " + uri, e);
        }
    }

    @Override public StorageCpmDocument loadMetaCpmDocument(String uri, String authorizationHeader) {
        return toCpmDocument(loadMetaDocument(uri, authorizationHeader));

    }

    public StorageCpmDocument toCpmDocument(StorageDocument storageDocument) {
        if (storageDocument == null) {
            return null;
        }
        if (storageDocument.document == null) {
            return new StorageCpmDocument(null, storageDocument.token);
        }

        return new StorageCpmDocument(
                new CpmDocument(
                        storageDocument.document,
                                                      provFactory,
                                                      cpmProvFactory,
                                                      cpmFactory
        ),
                                      storageDocument.token
        );
    }

    private static String getRequest(String url, String authorizationHeader) throws IOException {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet httpGet = new HttpGet(url);
            httpGet.setHeader("Authorization", authorizationHeader);
            try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
                int statusCode = response.getStatusLine().getStatusCode();
                if (statusCode != 200) {
                    throw new IOException("Unexpected response code: " + statusCode);
                }
                return EntityUtils.toString(response.getEntity());
            }
        }
    }

    private static String decodeData(String base64Data) {
        byte[] decodedBytes = Base64.getDecoder().decode(base64Data);
        return new String(decodedBytes, CHARSET);
    }
}
