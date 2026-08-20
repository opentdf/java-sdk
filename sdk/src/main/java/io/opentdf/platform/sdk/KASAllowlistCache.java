package io.opentdf.platform.sdk;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

class KASAllowlistCache {
    private static final Logger log = LoggerFactory.getLogger(KASAllowlistCache.class);
    Map<String, TimeStampedAllowList> cache;

    public KASAllowlistCache() {
        this.cache = new HashMap<>();
    }

    public void clear() {
        this.cache = new HashMap<>();
    }

    public Set<String> get(String platformURL) {
        log.debug("retrieving allowlist for platformURL = [{}]", platformURL);
        TimeStampedAllowList cachedValue = cache.get(platformURL);
        if (cachedValue == null) {
            log.debug("didn't find allowlist for platformURL = [{}]", platformURL);
            return null;
        }

        LocalDateTime fiveMinAgo = LocalDateTime.now().minus(5, ChronoUnit.MINUTES);
        if (fiveMinAgo.isAfter(cachedValue.timestamp)) {
            log.debug("cached allowlist is too old timestamp = [{}] for platformURL = [{}]",
                    cachedValue.timestamp, platformURL);
            cache.remove(platformURL);
            return null;
        }

        log.debug("successfully returned allowlist for platformURL = [{}]", platformURL);
        return new HashSet<>(cachedValue.allowlist);
    }

    public void store(String platformURL, Set<String> allowlist) {
        log.debug("storing allowlist into the cache for platformURL = [{}]", platformURL);
        cache.put(platformURL, new TimeStampedAllowList(
                Collections.unmodifiableSet(new HashSet<>(allowlist)), LocalDateTime.now()));
    }
}

class TimeStampedAllowList {
    Set<String> allowlist;
    LocalDateTime timestamp;

    public TimeStampedAllowList(Set<String> allowlist, LocalDateTime timestamp) {
        this.allowlist = allowlist;
        this.timestamp = timestamp;
    }
}
