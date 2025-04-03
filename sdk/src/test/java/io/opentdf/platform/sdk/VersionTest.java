package io.opentdf.platform.sdk;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

class VersionTest {

    @Test
    public void testParsingVersions() {
        assertThat(new Version("1.0.0")).isEqualTo(new Version(1, 0, 0, null));
    }

}