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
        assertEquals(Config.DEFAULT_SEGMENT_SIZE, config.getDefaultSegmentSize());
        assertTrue(config.isEnableEncryption());
        assertEquals(Config.TDFFormat.JSONFormat, config.getTdfFormat());
        assertEquals(Config.IntegrityAlgorithm.HS256, config.getIntegrityAlgorithm());
        assertEquals(Config.IntegrityAlgorithm.GMAC, config.getSegmentIntegrityAlgorithm());
        assertTrue(config.getAttributes().isEmpty());
        assertTrue(config.getKasInfoList().isEmpty());
        assertTrue(config.getRenderVersionInfoInManifest());
        assertFalse(config.isHexEncodeRootAndSegmentHashes());
    }

    @Test
    void withDataAttributes_shouldAddAttributes() throws AutoConfigureException {
        Config.TDFConfig config = Config.newTDFConfig(Config.withDataAttributes("https://example.com/attr/attr1/value/value1", "https://example.com/attr/attr2/value/value2"));
        assertEquals(2, config.getAttributes().size());
        assertTrue(config.getAttributes().contains(new Autoconfigure.AttributeValueFQN("https://example.com/attr/attr1/value/value1")));
        assertTrue(config.getAttributes().contains(new Autoconfigure.AttributeValueFQN("https://example.com/attr/attr2/value/value2")));
    }

    @Test
    void withKasInformation_shouldAddKasInfo() {
        Config.KASInfo kasInfo = new Config.KASInfo();
        kasInfo.setURL("http://example.com");
        kasInfo.setPublicKey("publicKey");
        kasInfo.setKID("r1");
        Config.TDFConfig config = Config.newTDFConfig(Config.withKasInformation(kasInfo));
        assertEquals(1, config.getKasInfoList().size());
        assertEquals(kasInfo, config.getKasInfoList().get(0));
    }

    @Test
    void withMetaData_shouldSetMetaData() {
        Config.TDFConfig config = Config.newTDFConfig(Config.withMetaData("metaData"));
        assertEquals("metaData", config.getMetaData());
    }

    @Test
    void withSegmentSize_shouldSetSegmentSize() {
        Config.TDFConfig config = Config.newTDFConfig(Config.withSegmentSize(Config.MIN_SEGMENT_SIZE));
        assertEquals(Config.MIN_SEGMENT_SIZE, config.getDefaultSegmentSize());
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
        Config.TDFConfig oldConfig = Config.newTDFConfig(Config.withTargetMode("1.0.1"));
        assertThat(oldConfig.getRenderVersionInfoInManifest()).isFalse();
        assertThat(oldConfig.isHexEncodeRootAndSegmentHashes()).isTrue();

        Config.TDFConfig newConfig = Config.newTDFConfig(Config.withTargetMode("100.0.1"));
        assertThat(newConfig.getRenderVersionInfoInManifest()).isTrue();
        assertThat(newConfig.isHexEncodeRootAndSegmentHashes()).isFalse();
    }


    @Test
    void withMimeType_shouldSetMimeType() {
        final String mimeType = "application/pdf";
        Config.TDFConfig config = Config.newTDFConfig(Config.withMimeType(mimeType));
        assertEquals(mimeType, config.getMimeType());
    }
}