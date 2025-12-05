package io.opentdf.platform;

import com.connectrpc.ResponseMessageKt;
import io.opentdf.platform.policy.Attribute;
import io.opentdf.platform.policy.attributes.ListAttributesRequest;
import io.opentdf.platform.policy.attributes.ListAttributesResponse;
import io.opentdf.platform.sdk.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Collections;

import java.util.List;
import java.util.stream.Collectors;

public class ListAttributes {
  private static final Logger logger = LogManager.getLogger(ListAttributes.class);

  public static void main(String[] args) {

    String clientId = "opentdf";
    String clientSecret = "secret";
    String platformEndpoint = "localhost:8080";

    SDKBuilder builder = new SDKBuilder();
    SDK sdk =
        builder
            .platformEndpoint(platformEndpoint)
            .clientSecret(clientId, clientSecret)
            .useInsecurePlaintextConnection(true)
            .build();

    ListAttributesRequest request =
        ListAttributesRequest.newBuilder().setNamespace("mynamespace.com").build();

    ListAttributesResponse resp =
        ResponseMessageKt.getOrThrow(
            sdk.getServices()
                .attributes()
                .listAttributesBlocking(request, Collections.emptyMap())
                .execute());

    List<Attribute> attributes = resp.getAttributesList();

    logger.info(
        "Successfully retrieved attributes {}",
        attributes.stream().map(Attribute::getFqn).collect(Collectors.joining(", ")));
  }
}
