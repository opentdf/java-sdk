package io.opentdf.platform.sdk;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class KASAllowlistCacheTest {

    private KASAllowlistCache cache;

    @BeforeEach
    void setUp() {
        cache = new KASAllowlistCache();
    }

    @Test
    void testStoreAndGet_WithinTimeLimit() {
        Set<String> allowlist = Set.of("https://kas1.example.org", "https://kas2.example.org");
        cache.store("https://platform.example.org", allowlist);

        Set<String> result = cache.get("https://platform.example.org");

        assertNotNull(result);
        assertEquals(2, result.size());
        assertTrue(result.contains("https://kas1.example.org"));
        assertTrue(result.contains("https://kas2.example.org"));
    }

    @Test
    void testStoreAndGet_AfterTimeLimit() {
        Set<String> allowlist = Set.of("https://kas.example.org");
        cache.store("https://platform.example.org", allowlist);

        TimeStampedAllowList expired = new TimeStampedAllowList(allowlist, LocalDateTime.now().minus(6, ChronoUnit.MINUTES));
        cache.cache.put("https://platform.example.org", expired);

        Set<String> result = cache.get("https://platform.example.org");

        assertNull(result);
    }

    @Test
    void testGet_EmptyCache() {
        Set<String> result = cache.get("https://platform.example.org");
        assertNull(result);
    }

    @Test
    void testGet_DifferentKey() {
        Set<String> allowlist = Set.of("https://kas.example.org");
        cache.store("https://platform.example.org", allowlist);

        Set<String> result = cache.get("https://other.example.org");

        assertNull(result);
    }

    @Test
    void testClearCache() {
        Set<String> allowlist = Set.of("https://kas.example.org");
        cache.store("https://platform.example.org", allowlist);

        cache.clear();

        Set<String> result = cache.get("https://platform.example.org");
        assertNull(result);
    }

    @Test
    void testStoreMultipleAndGet() {
        Set<String> allowlist1 = Set.of("https://kas1.example.org");
        Set<String> allowlist2 = Set.of("https://kas2.example.org");
        cache.store("https://platform1.example.org", allowlist1);
        cache.store("https://platform2.example.org", allowlist2);

        Set<String> result1 = cache.get("https://platform1.example.org");
        Set<String> result2 = cache.get("https://platform2.example.org");

        assertNotNull(result1);
        assertTrue(result1.contains("https://kas1.example.org"));
        assertNotNull(result2);
        assertTrue(result2.contains("https://kas2.example.org"));
    }
}
