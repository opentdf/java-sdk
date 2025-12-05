package io.opentdf.platform;

import com.connectrpc.ResponseMessageKt;
import io.opentdf.platform.authorization.Entity;
import io.opentdf.platform.authorization.EntityEntitlements;
import io.opentdf.platform.authorization.GetEntitlementsRequest;
import io.opentdf.platform.authorization.GetEntitlementsResponse;
import io.opentdf.platform.sdk.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Collections;

import java.util.List;

public class GetEntitlements {
  private static final Logger logger = LogManager.getLogger(GetEntitlements.class);

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

      GetEntitlementsRequest request =
          GetEntitlementsRequest.newBuilder()
              .addEntities(Entity.newBuilder().setId("entity-1").setClientId("opentdf"))
              .build();

      GetEntitlementsResponse getEntitlementsResponse =
          ResponseMessageKt.getOrThrow(
              sdk.getServices()
                  .authorization()
                  .getEntitlementsBlocking(request, Collections.emptyMap())
                  .execute());

      List<EntityEntitlements> entitlements = getEntitlementsResponse.getEntitlementsList();

      logger.info(
          "Successfully retrieved entitlements {}",
          entitlements.get(0).getAttributeValueFqnsList());
    } catch (Exception e) {
      logger.fatal("Failed to get entitlements", e);
    }
  }
}
