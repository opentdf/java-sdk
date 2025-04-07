package io.opentdf.platform.sdk;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

class Version implements Comparable<Version> {
    private final int major;
    private final int minor;
    private final int patch;
    private final String prereleaseAndMetadata;
    private static final Logger log = LoggerFactory.getLogger(Version.class);

    Pattern SEMVER_PATTERN = Pattern.compile("^(?<major>0|[1-9]\\d*)\\.(?<minor>0|[1-9]\\d*)\\.(?<patch>0|[1-9]\\d*)(?<prereleaseAndMetadata>\\D.*)?$");

    @Override
    public String toString() {
        return "Version{" +
                "major=" + major +
                ", minor=" + minor +
                ", patch=" + patch +
                ", prereleaseAndMetadata='" + prereleaseAndMetadata + '\'' +
                '}';
    }

    public Version(String semver) {
        var matcher = SEMVER_PATTERN.matcher(semver);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Invalid version format: " + semver);
        }
        this.major = Integer.parseInt(matcher.group("major"));
        this.minor = Optional.ofNullable(matcher.group("minor")).map(Integer::parseInt).orElse(0);
        this.patch = Optional.ofNullable(matcher.group("patch")).map(Integer::parseInt).orElse(0);
        this.prereleaseAndMetadata = matcher.group("prereleaseAndMetadata");
    }

    public Version(int major, int minor, int patch, @Nullable String prereleaseAndMetadata) {
        this.major = major;
        this.minor = minor;
        this.patch = patch;
        this.prereleaseAndMetadata = prereleaseAndMetadata;
    }

    @Override
    public int compareTo(@Nonnull Version o) {
        if (this.major != o.major) {
            return Integer.compare(this.major, o.major);
        }
        if (this.minor != o.minor) {
            return Integer.compare(this.minor, o.minor);
        }
        if (this.patch != o.patch) {
            return Integer.compare(this.patch, o.patch);
        }
        log.debug("ignoring prerelease and buildmetadata during comparision this = {} o = {}", this, o);
        return 0;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        Version version = (Version) o;
        return major == version.major && minor == version.minor && patch == version.patch;
    }

    @Override
    public int hashCode() {
        return Objects.hash(major, minor, patch);
    }
}
