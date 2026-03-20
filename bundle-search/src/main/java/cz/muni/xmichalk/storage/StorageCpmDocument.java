package cz.muni.xmichalk.storage;

import cz.muni.fi.cpm.model.CpmDocument;
import cz.muni.xmichalk.storage.storageDTO.Token;

public class StorageCpmDocument {
    public CpmDocument document;
    public Token token;

    public StorageCpmDocument(CpmDocument document, Token token) {
        this.document = document;
        this.token = token;
    }
}
