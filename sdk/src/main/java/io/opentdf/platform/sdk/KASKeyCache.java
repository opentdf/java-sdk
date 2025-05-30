package io.opentdf.platform.sdk;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;

/**
 * Class representing a cache for KAS (Key Access Server) information.
 * It stores key information along with a timestamp to manage the freshness of cached data.
 */
public class KASKeyCache {
    private static final Logger log = LoggerFactory.getLogger(KASKeyCache.class);
    Map<KASKeyRequest, TimeStampedKASInfo> cache;

    public KASKeyCache() {
        this.cache = new HashMap<>();
    }

    public void clear() {
        this.cache = new HashMap<>();
    }

    public Config.KASInfo get(String url, String algorithm) {
        log.debug("retrieving kasinfo for url = [{}], algorithm = [{}]", url, algorithm);
        KASKeyRequest cacheKey = new KASKeyRequest(url, algorithm);
        LocalDateTime now = LocalDateTime.now();
        TimeStampedKASInfo cachedValue = cache.get(cacheKey);

        if (cachedValue == null) {
            log.debug("didn't find kasinfo for url = [{}], algorithm = [{}]", url, algorithm);
            return null;
        }

        LocalDateTime aMinAgo = now.minus(5, ChronoUnit.MINUTES);
        if (aMinAgo.isAfter(cachedValue.timestamp)) {
            log.debug("cached value is too old timestamp = [{}] for url = [{}], algorithm = [{}]",
                    cachedValue.timestamp, url, algorithm);
            cache.remove(cacheKey);
            return null;
        }

        log.debug("successfully returned kasInfo = [{}], url = [{}], algorithm = [{}]", cachedValue.kasInfo, url, algorithm);
        return cachedValue.kasInfo;
    }

    public void store(Config.KASInfo kasInfo) {
        log.debug("storing kasInfo into the cache {}", kasInfo);
        KASKeyRequest cacheKey = new KASKeyRequest(kasInfo.URL, kasInfo.Algorithm);
        cache.put(cacheKey, new TimeStampedKASInfo(kasInfo, LocalDateTime.now()));
    }
}

/**
 * A class representing Key Aggregation Service (KAS) information along with a timestamp.
 * <p>
 * This class holds information related to KAS, as well as a timestamp indicating when the
 * information was recorded or generated. It encapsulates two main attributes: {@code kasInfo}
 * and {@code timestamp}.
 * <p>
 * The {@code kasInfo} field is an instance of {@code Config.KASInfo}, which contains the KAS-specific
 * data. The {@code timestamp} field is an instance of {@code LocalDateTime}, representing
 * the date and time when the KAS information was recorded.
 */
class TimeStampedKASInfo {
    Config.KASInfo kasInfo;
    LocalDateTime timestamp;

    public TimeStampedKASInfo(Config.KASInfo kasInfo, LocalDateTime timestamp) {
        this.kasInfo = kasInfo;
        this.timestamp = timestamp;
    }
}

/**
 * Represents a request for a Key Access Server (KAS) key.
 * This class is used to request keys using a specified URL and algorithm.
 *
 * This class also overrides equals and hashCode methods
 * to ensure proper functioning within hash-based collections.
 */
class KASKeyRequest {
    private String url;
    private String algorithm;

    public KASKeyRequest(String url, String algorithm) {
        this.url = url;
        this.algorithm = algorithm;
    }

    // Override equals and hashCode to ensure proper functioning of the HashMap
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || !(o instanceof KASKeyRequest)) return false;
        KASKeyRequest that = (KASKeyRequest) o;
       if (algorithm == null){
            return url.equals(that.url);
        }
        return url.equals(that.url) && algorithm.equals(that.algorithm);
    }

    @Override
    public int hashCode() {
        int result = 31 * url.hashCode();
        if (algorithm != null) {
            result = result + algorithm.hashCode();
        }
        return result;
    }
}