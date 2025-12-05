package io.opentdf.platform;

import com.connectrpc.ResponseMessageKt;
import io.opentdf.platform.policy.AttributeRuleTypeEnum;
import io.opentdf.platform.policy.Namespace;
import io.opentdf.platform.policy.attributes.CreateAttributeRequest;
import io.opentdf.platform.policy.attributes.CreateAttributeResponse;
import io.opentdf.platform.policy.namespaces.GetNamespaceRequest;
import io.opentdf.platform.sdk.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Collections;

import java.util.Arrays;

public class CreateAttribute {

  private static final Logger logger = LogManager.getLogger(CreateAttribute.class);

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

      Namespace namespace;
      String namespaceName = "mynamespace.com";

      try {
        namespace =
            ResponseMessageKt.getOrThrow(
                    sdk.getServices()
                        .namespaces()
                        .getNamespaceBlocking(
                            GetNamespaceRequest.newBuilder()
                                .setFqn("https://" + namespaceName)
                                .build(),
                            Collections.emptyMap())
                        .execute())
                .getNamespace();
      } catch (Exception e) {
        logger.error("Namespace '{}' not found", namespaceName);
        throw e;
      }

      CreateAttributeRequest createAttributeRequest =
          CreateAttributeRequest.newBuilder()
              .setNamespaceId(namespace.getId())
              .setName("test")
              .setRule(
                  AttributeRuleTypeEnum.forNumber(
                      AttributeRuleTypeEnum.ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF_VALUE))
              .addAllValues(Arrays.asList("test1", "test2"))
              .build();

      CreateAttributeResponse createAttributeResponse =
          ResponseMessageKt.getOrThrow(
              sdk.getServices()
                  .attributes()
                  .createAttributeBlocking(createAttributeRequest, Collections.emptyMap())
                  .execute());

      logger.info(
          "Successfully created attribute with ID: {}",
          createAttributeResponse.getAttribute().getId());
    } catch (Exception e) {
      logger.fatal("Failed to create attribute", e);
    }
  }
}
