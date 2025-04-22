package io.opentdf.platform.sdk;


import org.junit.jupiter.api.Test;

import static io.opentdf.platform.sdk.AddressNormalizer.normalizeAddress;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

class AddressNormalizerTest {

    @Test
    public void testAddressNormalizationWithHTTPSClient() {
        assertThat(normalizeAddress("http://example.org", false)).isEqualTo("https://example.org:80");
        // default to https if no scheme is provided
        assertThat(normalizeAddress("example.org:1234", false)).isEqualTo("https://example.org:1234");
    }

    @Test
    public void testAddressNormaliationWithInsecureHTTPClient() {
        assertThat(normalizeAddress("http://localhost:8080", true)).isEqualTo("http://localhost:8080");
        assertThat(normalizeAddress("https://example.org", true)).isEqualTo("https://example.org:443");
        // default to http if no scheme is provided
        assertThat(normalizeAddress("example.org:1234", true)).isEqualTo("http://example.org:1234");
    }
}