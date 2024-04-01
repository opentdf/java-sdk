package io.opentdf.platform.sdk;

/**
 * Interact with OpenTDF platform services and perform TDF data operations with
 * this object.
 */
public class SDK {
  private final String platformEndpoint;


  private SDK(String platformEndpoint) {
    this.platformEndpoint = platformEndpoint;
  }

  public String getPlatformEndpoint() {
    return this.platformEndpoint;
  }

  /**
   * Builder pattern for SDK objects
   */
  public static class Builder implements Cloneable {
    private String platformEndpoint;

    public Builder platformEndpoint(String platformEndpoint) {
      this.platformEndpoint = platformEndpoint;
      return this;
    }

    public SDK build() {
      return new SDK(this.platformEndpoint);
    }

    @Override public Builder clone() {
      try {
        return (Builder) super.clone();
      } catch (CloneNotSupportedException e) {
        throw new RuntimeException(e);
      }
    }
  }
}
