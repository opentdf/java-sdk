package io.opentdf.platform.sdk;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;

public class KASKeyCache {
    Map<KASKeyRequest, TimeStampedKASInfo> cache;

    public KASKeyCache() {
        this.cache = new HashMap<>();
    }

    public void clear() {
        this.cache = new HashMap<>();
    }

    public Config.KASInfo get(String url, String algorithm) {
        KASKeyRequest cacheKey = new KASKeyRequest(url, algorithm);
        LocalDateTime now = LocalDateTime.now();
        TimeStampedKASInfo cachedValue = cache.get(cacheKey);

        if (cachedValue == null) {
            return null;
        }

        LocalDateTime aMinAgo = now.minus(5, ChronoUnit.MINUTES);
        if (aMinAgo.isAfter(cachedValue.timestamp)) {
            cache.remove(cacheKey);
            return null;
        }

        return cachedValue.kasInfo;
    }

    public void store(Config.KASInfo kasInfo) {
        KASKeyRequest cacheKey = new KASKeyRequest(kasInfo.URL, kasInfo.Algorithm);
        cache.put(cacheKey, new TimeStampedKASInfo(kasInfo, LocalDateTime.now()));
    }
}

class TimeStampedKASInfo {
    Config.KASInfo kasInfo;
    LocalDateTime timestamp;

    public TimeStampedKASInfo(Config.KASInfo kasInfo, LocalDateTime timestamp) {
        this.kasInfo = kasInfo;
        this.timestamp = timestamp;
    }
}

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