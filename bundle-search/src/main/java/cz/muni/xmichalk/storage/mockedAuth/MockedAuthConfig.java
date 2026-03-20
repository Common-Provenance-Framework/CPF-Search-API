package cz.muni.xmichalk.storage.mockedAuth;

import java.util.List;

public class MockedAuthConfig {
    public boolean authorizedByDefault = false;
    public List<AuthEntry> authEntries;

    public MockedAuthConfig() {
    }

    public MockedAuthConfig(boolean authorizedByDefault, List<AuthEntry> authEntries) {
        this.authorizedByDefault = authorizedByDefault;
        this.authEntries = authEntries;
    }
}
