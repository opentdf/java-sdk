package io.opentdf.platform.sdk;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class VersionTest {

    @Test
    public void testParsingVersions() {
        assertThat(new Version("1.0.0")).isEqualTo(new Version(1, 0, 0, null));
        assertThat(new Version("1.2.1-alpha")).isEqualTo(new Version(1, 2, 1, "alpha a build"));
        // ignore anything but the version
        assertThat(new Version("1.2.1-alpha+build.123")).isEqualTo(new Version(1, 2, 1, "beta build.1234"));
    }

    @Test
    public void testComparingVersions() {
        assertThat(new Version("1.0.0")).isLessThan(new Version("1.0.1"));
        assertThat(new Version("1.0.1")).isGreaterThan(new Version("1.0.0"));

        assertThat(new Version("500.0.1")).isLessThan(new Version("500.1.1"));
        assertThat(new Version("500.1.1")).isGreaterThan(new Version("500.0.1"));

        // ignore anything but the version
        assertThat(new Version("1.0.1-alpha+thisbuild")).isEqualByComparingTo(new Version("1.0.1-beta+thatbuild"));
    }
}
