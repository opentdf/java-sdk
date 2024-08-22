package io.opentdf.platform.sdk;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.*;

class KASKeyCacheTest {

    private KASKeyCache kasKeyCache;
    private Config.KASInfo kasInfo1;
    private Config.KASInfo kasInfo2;

    @BeforeEach
    void setUp() {
        kasKeyCache = new KASKeyCache();
        kasInfo1 = new Config.KASInfo();
        kasInfo1.Algorithm = "rsa:2048";
        kasInfo1.URL = "https://example.com/kas1";
        kasInfo1.KID = "kid1";
        kasInfo1.PublicKey = "publicKey1";
        kasInfo2 = new Config.KASInfo();
        kasInfo2.URL = "https://example.com/kas2";
        kasInfo2.Algorithm = "ec:secp256r1";
        kasInfo2.KID = "kid2";
        kasInfo2.PublicKey = "publicKey2";
    }

    @Test
    void testStoreAndGet_WithinTimeLimit() {
        // Store an item in the cache
        kasKeyCache.store(kasInfo1);

        // Retrieve the item within the time limit
        Config.KASInfo result = kasKeyCache.get("https://example.com/kas1", "rsa:2048");

        // Ensure the item was correctly retrieved
        assertNotNull(result);
        assertEquals("https://example.com/kas1", result.URL);
        assertEquals("rsa:2048", result.Algorithm);
        assertEquals("kid1", result.KID);
        assertEquals("publicKey1", result.PublicKey);
    }

    @Test
    void testStoreAndGet_AfterTimeLimit() {
        // Store an item in the cache
        kasKeyCache.store(kasInfo1);

        // Simulate time passing by modifying the timestamp directly
        KASKeyRequest cacheKey = new KASKeyRequest("https://example.com/kas1", "rsa:2048");
        TimeStampedKASInfo timeStampedKASInfo = new TimeStampedKASInfo(kasInfo1, LocalDateTime.now().minus(6, ChronoUnit.MINUTES));
        kasKeyCache.cache.put(cacheKey, timeStampedKASInfo);

        // Attempt to retrieve the item after the time limit
        Config.KASInfo result = kasKeyCache.get("https://example.com/kas1", "rsa:2048");

        // Ensure the item was not retrieved (it should have expired)
        assertNull(result);
    }

    @Test
    void testStoreAndGet_WithNullAlgorithm() {
        // Store an item in the cache with a null algorithm
        kasInfo1 = new Config.KASInfo();
        kasInfo1.URL = "https://example.com/kas1";
        kasInfo1.KID = "kid1";
        kasInfo1.PublicKey = "publicKey1";
        kasKeyCache.store(kasInfo1);

        // Retrieve the item with a null algorithm
        Config.KASInfo result = kasKeyCache.get("https://example.com/kas1", null);

        // Ensure the item was correctly retrieved
        assertNotNull(result);
        assertEquals("https://example.com/kas1", result.URL);
        assertNull(result.Algorithm);
        assertEquals("kid1", result.KID);
        assertEquals("publicKey1", result.PublicKey);
    }

    @Test
    void testClearCache() {
        // Store an item in the cache
        kasKeyCache.store(kasInfo1);

        // Clear the cache
        kasKeyCache.clear();

        // Attempt to retrieve the item after clearing the cache
        Config.KASInfo result = kasKeyCache.get("https://example.com/kas1", "rsa:2048");

        // Ensure the item was not retrieved (the cache should be empty)
        assertNull(result);
    }

    @Test
    void testStoreMultipleItemsAndGet() {
        // Store multiple items in the cache
        kasKeyCache.store(kasInfo1);
        kasKeyCache.store(kasInfo2);

        // Retrieve each item and ensure they were correctly stored and retrieved
        Config.KASInfo result1 = kasKeyCache.get("https://example.com/kas1", "rsa:2048");
        Config.KASInfo result2 = kasKeyCache.get("https://example.com/kas2", "ec:secp256r1");

        assertNotNull(result1);
        assertEquals("https://example.com/kas1", result1.URL);
        assertEquals("rsa:2048", result1.Algorithm);

        assertNotNull(result2);
        assertEquals("https://example.com/kas2", result2.URL);
        assertEquals("ec:secp256r1", result2.Algorithm);
    }

    @Test
    void testEqualsAndHashCode() {
        // Create two identical KASKeyRequest objects
        KASKeyRequest keyRequest1 = new KASKeyRequest("https://example.com/kas1", "rsa:2048");
        KASKeyRequest keyRequest2 = new KASKeyRequest("https://example.com/kas1", "rsa:2048");

        // Ensure that equals and hashCode work as expected
        assertEquals(keyRequest1, keyRequest2);
        assertEquals(keyRequest1.hashCode(), keyRequest2.hashCode());
    }
}