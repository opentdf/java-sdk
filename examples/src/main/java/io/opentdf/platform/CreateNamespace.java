package io.opentdf.platform;

import com.connectrpc.ResponseMessageKt;
import io.opentdf.platform.policy.namespaces.CreateNamespaceRequest;
import io.opentdf.platform.policy.namespaces.CreateNamespaceResponse;
import io.opentdf.platform.sdk.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Collections;

public class CreateNamespace {

  private static final Logger logger = LogManager.getLogger(CreateNamespace.class);

  public static void main(String[] args) {

    String clientId = "opentdf";
    String clientSecret = "secret";
    String platformEndpoint = "localhost:8080";

    SDKBuilder builder = new SDKBuilder();

    try (SDK sdk =
        builder
            .platformEndpoint(platformEndpoint)
            .clientSecret(clientId, clientSecret)
            .useInsecurePlaintextConnection(true)
            .build()) {

      CreateNamespaceRequest createNamespaceRequest =
          CreateNamespaceRequest.newBuilder().setName("mynamespace.com").build();

      CreateNamespaceResponse createNamespaceResponse =
          ResponseMessageKt.getOrThrow(
              sdk.getServices()
                  .namespaces()
                  .createNamespaceBlocking(createNamespaceRequest, Collections.emptyMap())
                  .execute());

      logger.info(
          "Successfully created namespace with ID: {}",
          createNamespaceResponse.getNamespace().getId());

    } catch (Exception e) {
      logger.fatal("Failed to create namespace", e);
    }
  }
}
