package cz.muni.xmichalk.storage;

import java.nio.file.AccessDeniedException;

public interface IStorage {
    StorageCpmDocument loadCpmDocument(String uri, EBundlePart part, String authorizationHeader)
            throws AccessDeniedException;

    StorageCpmDocument loadMetaCpmDocument(String uri, String authorizationHeader) throws AccessDeniedException;
}
