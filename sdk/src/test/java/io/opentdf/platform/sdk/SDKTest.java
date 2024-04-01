package io.opentdf.platform.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.logging.Logger;
import org.junit.jupiter.api.Test;

class SDKTest {
  private static final Logger logger = Logger.getLogger(SDKTest.class.getName());

  @Test
  public void testBuilderPlatformEndpoint() {
    SDK sdk = new SDK.Builder().platformEndpoint("https://kas.dev").build();
    assertEquals("https://kas.dev", sdk.getPlatformEndpoint());
  }
}
