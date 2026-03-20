package cz.muni.xmichalk.util;

import org.openprovenance.prov.interop.InteropFramework;
import org.openprovenance.prov.model.Document;
import org.openprovenance.prov.model.interop.Formats;
import org.openprovenance.prov.model.interop.InteropMediaType;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class ProvDocumentUtils {
    public static final Charset charset = java.nio.charset.StandardCharsets.UTF_8;

    public static String serialize(Document document, Formats.ProvFormat format) {
        InteropFramework interop = new InteropFramework();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        interop.writeDocument(outputStream, document, ProvFormatToIntermediaType(format), false);
        String serialized = outputStream.toString(charset);
        return finalizeAfterSerialization(serialized, format);
    }

    public static void serializeIntoFile(Path filePath, Document document, Formats.ProvFormat format)
            throws IOException {
        String string = serialize(document, format);
        Files.writeString(filePath, string, charset);
    }

    public static String finalizeAfterSerialization(String serializedDocument, Formats.ProvFormat format) {
        if (format == Formats.ProvFormat.JSON) {
            serializedDocument = ProvJsonUtils.removeExplicitBundleId(serializedDocument);
        }

        return serializedDocument;
    }

    public static Document deserialize(String serialized, Formats.ProvFormat format) throws IOException {
        serialized = prepareForDeserialization(serialized, format);
        InteropFramework interop = new InteropFramework();
        InputStream inputStream =
                new ByteArrayInputStream(serialized.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return interop.readDocument(inputStream, format);
    }

    public static Document deserializeFile(Path filePath, Formats.ProvFormat format) throws IOException {
        String serialized = Files.readString(filePath, StandardCharsets.UTF_8);
        return deserialize(serialized, format);
    }

    public static String prepareForDeserialization(String serializedDocument, Formats.ProvFormat format) {
        if (format == Formats.ProvFormat.JSON) {
            serializedDocument = ProvJsonUtils.prepareJsonForDeserialization(serializedDocument);
        }

        return serializedDocument;
    }

    public static String ProvFormatToIntermediaType(Formats.ProvFormat format) {
        return switch (format) {
            case JSON -> InteropMediaType.MEDIA_APPLICATION_JSON;
            case JSONLD -> InteropMediaType.MEDIA_APPLICATION_JSONLD;
            case PROVN -> InteropMediaType.MEDIA_TEXT_PROVENANCE_NOTATION;
            case TURTLE -> InteropMediaType.MEDIA_TEXT_TURTLE;
            case TRIG -> InteropMediaType.MEDIA_APPLICATION_TRIG;
            case RDFXML -> InteropMediaType.MEDIA_APPLICATION_XML;
            default -> throw new IllegalStateException("Switch case for: " + format + " is not defined.");
        };
    }
}
