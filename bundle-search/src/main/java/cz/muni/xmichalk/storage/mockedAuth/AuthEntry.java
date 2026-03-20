package cz.muni.xmichalk.storage.mockedAuth;

public record AuthEntry(String authHeader, String uri, Boolean authorized) {
}
