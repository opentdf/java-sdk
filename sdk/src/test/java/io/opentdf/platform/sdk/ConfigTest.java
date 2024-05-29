package io.opentdf.platform.sdk;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
    }

    @Test
    void withDataAttributes_shouldAddAttributes() {
        Config.TDFConfig config = Config.newTDFConfig(Config.withDataAttributes("attr1", "attr2"));
        assertEquals(2, config.attributes.size());
        assertTrue(config.attributes.contains("attr1"));
        assertTrue(config.attributes.contains("attr2"));
    }

    @Test
    void withKasInformation_shouldAddKasInfo() {
        Config.KASInfo kasInfo = new Config.KASInfo();
        kasInfo.URL = "http://example.com";
        kasInfo.PublicKey = "publicKey";
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
        Config.TDFConfig config = Config.newTDFConfig(Config.withSegmentSize(1024));
        assertEquals(1024, config.defaultSegmentSize);
    }
}