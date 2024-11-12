package io.opentdf.platform;
import io.opentdf.platform.sdk.*;

import java.util.concurrent.ExecutionException;

import io.opentdf.platform.policy.AttributeRuleTypeEnum;

import io.opentdf.platform.policy.attributes.*;
import io.opentdf.platform.policy.Attribute;

import java.util.List;

public class ListAttributes {
    public static void main(String[] args) throws ExecutionException, InterruptedException{

        String clientId = "opentdf";
        String clientSecret = "secret";
        String platformEndpoint = "localhost:8080";

        SDKBuilder builder = new SDKBuilder();
        SDK sdk = builder.platformEndpoint(platformEndpoint)
                .clientSecret(clientId, clientSecret).useInsecurePlaintextConnection(true)
                .build();

        ListAttributesRequest request = ListAttributesRequest.newBuilder()
        .setNamespace("mynamespace.com").build();

        ListAttributesResponse resp = sdk.getServices().attributes().listAttributes(request).get();

        List<Attribute> attributes = resp.getAttributesList();

        System.out.println(resp.getAttributesCount());
    }
}
