package cz.muni.xmichalk.storage;

import cz.muni.xmichalk.MockedStorage;
import cz.muni.xmichalk.TestDocumentProvider;
import cz.muni.xmichalk.storage.mockedAuth.AuthEntry;
import cz.muni.xmichalk.storage.mockedAuth.MockedAuthConfig;
import cz.muni.xmichalk.storage.mockedAuth.MockedAuthStorage;
import org.junit.jupiter.params.ParameterizedTest;

import java.nio.file.AccessDeniedException;
import java.util.List;
import java.util.stream.Stream;

public class MockedAuthStorageTest {
    private static final String authHeader1 = "Bearer token1";
    private static final String authHeader2 = "Bearer token2";

    private static final String uri1 = TestDocumentProvider.samplingBundle_V1.getBundleId().getUri();
    private static final String uri2 = TestDocumentProvider.processingBundle_V1.getBundleId().getUri();
    private static final String metaUri1 = TestDocumentProvider.samplingBundle_V0_meta.getBundleId().getUri();
    private static final String metaUri2 = TestDocumentProvider.processingBundle_V0_meta.getBundleId().getUri();

    private static final MockedAuthConfig config1 = new MockedAuthConfig(
            false,
            List.of(
                    new AuthEntry(authHeader1, uri1, true),
                    new AuthEntry(authHeader2, uri2, true)
            )
    );
    private static final MockedAuthConfig config2 = new MockedAuthConfig(
            true,
                                                                         List.of(
                                                                                 new AuthEntry(
                                                                                         authHeader1,
                                                                                         uri2,
                                                                                         false
                                                                                 ), new AuthEntry(authHeader2, uri1, false)
                                                                         )
    );

    private static final MockedAuthConfig config3 = new MockedAuthConfig(
            false,
                                                                         List.of(
                                                                                 new AuthEntry(
                                                                                         authHeader1,
                                                                                         metaUri1,
                                                                                         true
                                                                                 ), new AuthEntry(authHeader2, metaUri2, true)
                                                                         )
    );

    private static final MockedAuthConfig config4 = new MockedAuthConfig(
            true,
                                                                         List.of(
                                                                                 new AuthEntry(
                                                                                         authHeader1,
                                                                                         metaUri2,
                                                                                         false
                                                                                 ), new AuthEntry(authHeader2, metaUri1, false)
                                                                         )
    );

    static Stream<Object[]> loadCpmDocumentParams() {
        return Stream.of(
                new Object[]{uri1, EBundlePart.Whole, authHeader1, config1, true},
                new Object[]{uri2, EBundlePart.Whole, authHeader1, config1, false},
                new Object[]{uri2, EBundlePart.Whole, authHeader2, config1, true},
                new Object[]{uri1, EBundlePart.Whole, authHeader2, config1, false},

                new Object[]{uri1, EBundlePart.Whole, authHeader1, config2, true},
                new Object[]{uri2, EBundlePart.Whole, authHeader1, config2, false},
                new Object[]{uri2, EBundlePart.Whole, authHeader2, config2, true},
                new Object[]{uri1, EBundlePart.Whole, authHeader2, config2, false},

                new Object[]{uri1, EBundlePart.TraversalInformation, authHeader1, config1, true},
                new Object[]{uri1, EBundlePart.DomainSpecific, authHeader1, config1, true},
                new Object[]{uri2, EBundlePart.TraversalInformation, authHeader1, config1, false},
                new Object[]{uri2, EBundlePart.DomainSpecific, authHeader1, config1, false}
        );
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("loadCpmDocumentParams")
    public void testLoadCpmDocument(
            String uri,
            EBundlePart part,
            String authorizationHeader,
            MockedAuthConfig config,
            boolean shouldPass
    ) {
        Boolean passed = null;
        StorageCpmDocument document = null;
        MockedAuthStorage storage = new MockedAuthStorage(new MockedStorage(), config);

        try {
            document = storage.loadCpmDocument(uri, part, authorizationHeader);
            passed = true;
        } catch (AccessDeniedException e) {
            passed = false;
        }

        assert passed == shouldPass;

        if (shouldPass) {
            assert document != null;
            assert document.document != null;
        }
    }

    static Stream<Object[]> loadMetaCpmDocumentParams() {
        return Stream.of(
                new Object[]{metaUri1, authHeader1, config3, true},
                new Object[]{metaUri2, authHeader1, config3, false},
                new Object[]{metaUri2, authHeader2, config3, true},
                new Object[]{metaUri1, authHeader2, config3, false},

                new Object[]{metaUri1, authHeader1, config4, true},
                new Object[]{metaUri2, authHeader1, config4, false},
                new Object[]{metaUri2, authHeader2, config4, true},
                new Object[]{metaUri1, authHeader2, config4, false}
        );
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.MethodSource("loadMetaCpmDocumentParams")
    public void testLoadMetaCpmDocument(
            String uri,
            String authorizationHeader,
            MockedAuthConfig config,
            boolean shouldPass
    ) {
        Boolean passed = null;
        StorageCpmDocument document = null;
        MockedAuthStorage storage = new MockedAuthStorage(new MockedStorage(), config);

        try {
            document = storage.loadMetaCpmDocument(uri, authorizationHeader);
            passed = true;
        } catch (AccessDeniedException e) {
            passed = false;
        }

        assert passed == shouldPass;

        if (shouldPass) {
            assert document != null;
            assert document.document != null;
        }
    }
}
