package io.opentdf.platform.sdk.nanotdf;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.nio.ByteBuffer;
import static org.junit.jupiter.api.Assertions.*;

class ResourceLocatorTest {
    private ResourceLocator locator;

    @BeforeEach
    void setUp() {
        locator = new ResourceLocator();
    }

    @Test
    void creatingResourceLocatorWithHttpUrl() {
        String url = "http://test.com";
        locator = new ResourceLocator(url);
        assertEquals(url, locator.getResourceUrl());
    }

    @Test
    void creatingResourceLocatorWithHttpsUrl() {
        String url = "https://test.com";
        locator = new ResourceLocator(url);
        assertEquals(url, locator.getResourceUrl());
    }

    @Test
    void creatingResourceLocatorWithUnsupportedProtocol() {
        String url = "ftp://test.com";
        assertThrows(RuntimeException.class, () -> new ResourceLocator(url));
    }

    @Test
    void creatingResourceLocatorFromBytes() {
        String url = "http://test.com";
        ResourceLocator original = new ResourceLocator(url);
        byte[] buffer = new byte[original.getTotalSize()];
        original.writeIntoBuffer(ByteBuffer.wrap(buffer));
        locator = new ResourceLocator(ByteBuffer.wrap(buffer));
        assertEquals(url, locator.getResourceUrl());
    }

    @Test
    void writingResourceLocatorIntoBufferWithInsufficientSize() {
        String url = "http://test.com";
        locator = new ResourceLocator(url);
        ByteBuffer buffer = ByteBuffer.allocate(1); // Buffer with insufficient size
        assertThrows(RuntimeException.class, () -> locator.writeIntoBuffer(buffer));
    }
}