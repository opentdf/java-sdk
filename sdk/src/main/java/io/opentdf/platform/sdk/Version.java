package io.opentdf.platform.sdk;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Optional;
import java.util.regex.Pattern;

class Version implements Comparable<Version> {
    private final int major;
    private final Integer minor;
    private final Integer patch;
    private final String prerelease;
    private static final Logger log = LoggerFactory.getLogger(Version.class);

    Pattern SEMVER_PATTERN = Pattern.compile("^(?<major>0|[1-9]\\d*)\\.(?<minor>0|[1-9]\\d*)\\.(?<patch>0|[1-9]\\d*)(?:-(?<prerelease>(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\\.(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\\+(?<buildmetadata>[0-9a-zA-Z-]+(?:\\.[0-9a-zA-Z-]+)*))?$\n");

    @Override
    public String toString() {
        return "Version{" +
                "major=" + major +
                ", minor=" + minor +
                ", patch=" + patch +
                ", prerelease='" + prerelease + '\'' +
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
        this.prerelease = matcher.group("prerelease");
    }

    public Version(int major, @Nullable Integer minor, @Nullable Integer patch, @Nullable String prerelease) {
        this.major = major;
        this.minor = minor;
        this.patch = patch;
        this.prerelease = prerelease;
    }

    @Override
    public int compareTo(@Nonnull Version o) {
        if (this.major != o.major) {
            return Integer.compare(this.major, o.major);
        }
        int thisMinor = this.minor == null ? 0 : this.minor;
        int otherMinor = o.minor == null ? 0 : o.minor;
        if (thisMinor != otherMinor) {
            return Integer.compare(thisMinor, otherMinor);
        }
        int thisPatch = this.patch == null ? 0 : this.patch;
        int otherPatch = o.patch == null ? 0 : o.patch;
        if (thisPatch != otherPatch) {
            return Integer.compare(thisPatch, otherPatch);
        }
        log.debug("ignoring prerelease version during comparision this = {} o = {}", this, o);
        return 0;
    }
}
