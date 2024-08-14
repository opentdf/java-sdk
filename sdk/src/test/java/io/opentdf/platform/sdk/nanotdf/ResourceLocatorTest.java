package io.opentdf.platform.sdk.nanotdf;

import java.nio.ByteBuffer;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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

    @ParameterizedTest
    @MethodSource("provideUrlsAndIdentifiers")
    void creatingResourceLocatorWithDifferentIdentifiers(String url, String identifier, int expectedLength) {
        locator = new ResourceLocator(url, identifier);
        assertEquals(url, locator.getResourceUrl());
        assertEquals(identifier, locator.getIdentifierString());
        assertEquals(expectedLength, locator.getIdentifier().length);
    }

    private static Stream<Arguments> provideUrlsAndIdentifiers() {
        return Stream.of(
                Arguments.of("http://test.com", "F", 2),
                Arguments.of("http://test.com", "e0", 2),
                Arguments.of("http://test.com", "e0e0e0e0", 8),
                Arguments.of("http://test.com", "e0e0e0e0e0e0e0e0", 32),
                Arguments.of("https://test.com", "e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0",32 )
        );
    }

    @Test
    void creatingResourceLocatorUnexpectedIdentifierType() {
        String url = "http://test.com";
        String identifier = "unexpectedIdentifierunexpectedIdentifier";
        assertThrows(IllegalArgumentException.class, () -> new ResourceLocator(url, identifier));
    }

    @Test
    void creatingResourceLocatorFromBufferWithIdentifier() {
        String url = "http://test.com";
        String identifier = "e0";
        ResourceLocator original = new ResourceLocator(url, identifier);
        byte[] buffer = new byte[original.getTotalSize()];
        original.writeIntoBuffer(ByteBuffer.wrap(buffer));
        locator = new ResourceLocator(ByteBuffer.wrap(buffer));
        assertEquals(url, locator.getResourceUrl());
        assertArrayEquals(identifier.getBytes(), locator.getIdentifier());
    }
}
