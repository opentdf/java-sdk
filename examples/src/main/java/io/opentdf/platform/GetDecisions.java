package io.opentdf.platform;

import com.connectrpc.ResponseMessageKt;
import io.opentdf.platform.authorization.DecisionRequest;
import io.opentdf.platform.authorization.DecisionResponse;
import io.opentdf.platform.authorization.Entity;
import io.opentdf.platform.authorization.EntityChain;
import io.opentdf.platform.authorization.GetDecisionsRequest;
import io.opentdf.platform.authorization.GetDecisionsResponse;
import io.opentdf.platform.authorization.ResourceAttribute;
import io.opentdf.platform.policy.Action;
import io.opentdf.platform.sdk.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Collections;

import java.util.List;

public class GetDecisions {

  private static final Logger logger = LogManager.getLogger(GetDecisions.class);

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

      GetDecisionsRequest request =
          GetDecisionsRequest.newBuilder()
              .addDecisionRequests(
                  DecisionRequest.newBuilder()
                      .addEntityChains(
                          EntityChain.newBuilder()
                              .setId("ec1")
                              .addEntities(
                                  Entity.newBuilder().setId("entity-1").setClientId("opentdf")))
                      .addActions(
                          Action.newBuilder()
                              .setStandard(Action.StandardAction.STANDARD_ACTION_DECRYPT))
                      .addResourceAttributes(
                          ResourceAttribute.newBuilder()
                              .setResourceAttributesId("resource-attribute-1")
                              .addAttributeValueFqns(
                                  "https://mynamespace.com/attr/test/value/test1")))
              .build();

      GetDecisionsResponse getDecisionsResponse =
          ResponseMessageKt.getOrThrow(
              sdk.getServices()
                  .authorization()
                  .getDecisionsBlocking(request, Collections.emptyMap())
                  .execute());

      List<DecisionResponse> decisions = getDecisionsResponse.getDecisionResponsesList();

      logger.info("Successfully retrieved decision {}", decisions.get(0).getDecision());
    } catch (Exception e) {
      logger.fatal("Failed to get decisions", e);
    }
  }
}
