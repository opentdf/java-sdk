package io.opentdf.platform.sdk;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class ConfigTest {

    @Test
    void newTDFConfig_shouldCreateDefaultConfig() {
        Config.TDFConfig config = Config.newTDFConfig();
        assertEquals(Config.DEFAULT_SEGMENT_SIZE, config.defaultSegmentSize);
        assertTrue(config.enableEncryption);
        assertEquals(Config.TDFFormat.JSONFormat, config.tdfFormat);
        assertEquals(Config.IntegrityAlgorithm.HS256, config.integrityAlgorithm);
        assertEquals(Config.IntegrityAlgorithm.GMAC, config.segmentIntegrityAlgorithm);
        assertTrue(config.attributes.isEmpty());
        assertTrue(config.kasInfoList.isEmpty());
        assertTrue(config.renderVersionInfoInManifest);
        assertFalse(config.hexEncodeRootAndSegmentHashes);
    }

    @Test
    void withDataAttributes_shouldAddAttributes() throws AutoConfigureException {
        Config.TDFConfig config = Config.newTDFConfig(Config.withDataAttributes("https://example.com/attr/attr1/value/value1", "https://example.com/attr/attr2/value/value2"));
        assertEquals(2, config.attributes.size());
        assertTrue(config.attributes.contains(new Autoconfigure.AttributeValueFQN("https://example.com/attr/attr1/value/value1")));
        assertTrue(config.attributes.contains(new Autoconfigure.AttributeValueFQN("https://example.com/attr/attr2/value/value2")));
    }

    @Test
    void withKasInformation_shouldAddKasInfo() {
        Config.KASInfo kasInfo = new Config.KASInfo();
        kasInfo.URL = "http://example.com";
        kasInfo.PublicKey = "publicKey";
        kasInfo.KID = "r1";
        Config.TDFConfig config = Config.newTDFConfig(Config.withKasInformation(kasInfo));
        assertEquals(1, config.kasInfoList.size());
        assertEquals(kasInfo, config.kasInfoList.get(0));
    }

    @Test
    void withMetaData_shouldSetMetaData() {
        Config.TDFConfig config = Config.newTDFConfig(Config.withMetaData("metaData"));
        assertEquals("metaData", config.metaData);
    }

    @Test
    void withSegmentSize_shouldSetSegmentSize() {
        Config.TDFConfig config = Config.newTDFConfig(Config.withSegmentSize(Config.MIN_SEGMENT_SIZE));
        assertEquals(Config.MIN_SEGMENT_SIZE, config.defaultSegmentSize);
    }

    @Test
    void withSegmentSize_shouldIgnoreSegmentSize() {
        try {
            Config.withSegmentSize(1024);
            fail("Expected exception");
        } catch (IllegalArgumentException e) {
            // expected
        }
    }

    @Test
    void withCompatibilityModeShouldSetFieldsCorrectly() {
        Config.TDFConfig config = Config.newTDFConfig(Config.withTargetMode("1.0.1"));
        assertThat(config.renderVersionInfoInManifest).isFalse();
        assertThat(config.hexEncodeRootAndSegmentHashes).isTrue();
    }


    @Test
    void withMimeType_shouldSetMimeType() {
        final String mimeType = "application/pdf";
        Config.TDFConfig config = Config.newTDFConfig(Config.withMimeType(mimeType));
        assertEquals(mimeType, config.mimeType);
    }
}