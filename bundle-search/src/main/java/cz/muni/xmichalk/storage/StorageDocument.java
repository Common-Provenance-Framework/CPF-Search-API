package cz.muni.xmichalk.storage;

import cz.muni.xmichalk.storage.storageDTO.Token;
import org.openprovenance.prov.model.Document;

public class StorageDocument {
    public Document document;
    public Token token;

    public StorageDocument(Document document, Token token) {
        this.document = document;
        this.token = token;
    }
}
