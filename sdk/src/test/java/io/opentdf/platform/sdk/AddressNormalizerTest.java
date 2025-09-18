package io.opentdf.platform.sdk;


import org.junit.jupiter.api.Test;

import static io.opentdf.platform.sdk.AddressNormalizer.normalizeAddress;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AddressNormalizerTest {

    @Test
    void testAddressNormalizationWithHTTPSClient() {
        assertThat(normalizeAddress("http://example.org", false)).isEqualTo("https://example.org:443");
        // default to https if no scheme is provided
        assertThat(normalizeAddress("example.org:1234", false)).isEqualTo("https://example.org:1234");
        assertThat(normalizeAddress("ftp://example.org", false)).isEqualTo("https://example.org:443");
        assertThat(normalizeAddress("keycloak.vm", false)).isEqualTo("https://keycloak.vm:443");
    }

    @Test
    void testAddressNormaliationWithInsecureHTTPClient() {
        assertThat(normalizeAddress("http://localhost:8080", true)).isEqualTo("http://localhost:8080");
        assertThat(normalizeAddress("http://example.org", true)).isEqualTo("http://example.org:80");
        // default to http if no scheme is provided
        assertThat(normalizeAddress("example.org:1234", true)).isEqualTo("http://example.org:1234");
        assertThat(normalizeAddress("sftp://example.org", true)).isEqualTo("http://example.org:80");
        assertThat(normalizeAddress("keycloak.vm", true)).isEqualTo("http://keycloak.vm:80");
    }

    @Test
    void testAddressNormalizationWithInvalidPort() {
        var thrown = assertThrows(SDKException.class, () -> normalizeAddress("example.org:notaport", true));
        assertThat(thrown.getMessage()).contains("example.org:notaport");

        thrown = assertThrows(SDKException.class, () -> normalizeAddress("http://example.org:notaport", true));
        assertThat(thrown.getMessage()).contains("http://example.org:notaport");
    }
}
