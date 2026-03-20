package cz.muni.xmichalk.storage.mockedAuth;

import cz.muni.xmichalk.storage.EBundlePart;
import cz.muni.xmichalk.storage.IStorage;
import cz.muni.xmichalk.storage.StorageCpmDocument;

import java.nio.file.AccessDeniedException;

public class MockedAuthStorage implements IStorage {
    private final IStorage storage;
    private final MockedAuthConfig config;

    public MockedAuthStorage(IStorage storage, MockedAuthConfig config) {
        this.storage = storage;
        this.config = config;
    }

    @Override public StorageCpmDocument loadCpmDocument(String uri, EBundlePart part, String authorizationHeader)
            throws AccessDeniedException {
        if (isAuthorized(uri, part, authorizationHeader)) {
            return storage.loadCpmDocument(uri, part, authorizationHeader);
        } else {
            throw new AccessDeniedException("Not authorized to access resource: " + uri);
        }
    }

    @Override public StorageCpmDocument loadMetaCpmDocument(final String uri, final String authorizationHeader)
            throws AccessDeniedException {
        if (isAuthorized(uri, EBundlePart.Whole, authorizationHeader)) {
            return storage.loadMetaCpmDocument(uri, authorizationHeader);
        } else {
            throw new AccessDeniedException("Not authorized to access resource: " + uri);
        }
    }

    private boolean isAuthorized(String uri, EBundlePart part, String authorizationHeader) {
        AuthEntry authEntry = config.authEntries.stream()
                .filter(entry -> entry.authHeader().equals(authorizationHeader) && entry.uri().equals(uri)).findFirst()
                .orElse(null);
        if (authEntry != null) {
            return authEntry.authorized();
        }

        return config.authorizedByDefault;
    }
}
