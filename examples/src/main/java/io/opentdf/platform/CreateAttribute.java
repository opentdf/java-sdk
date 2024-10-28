package io.opentdf.platform;
import io.opentdf.platform.sdk.*;

import java.util.concurrent.ExecutionException;

import io.opentdf.platform.policy.AttributeRuleTypeEnum;

import io.opentdf.platform.policy.attributes.*;
import io.opentdf.platform.policy.Attribute;

import java.util.Arrays;

public class CreateAttribute {
    public static void main(String[] args) throws ExecutionException, InterruptedException{

        String clientId = "opentdf";
        String clientSecret = "secret";
        String platformEndpoint = "localhost:8080";

        SDKBuilder builder = new SDKBuilder();
        SDK sdk = builder.platformEndpoint(platformEndpoint)
                .clientSecret(clientId, clientSecret).useInsecurePlaintextConnection(true)
                .build();

        CreateAttributeRequest request = CreateAttributeRequest.newBuilder()
        .setNamespaceId("877990d1-609b-42ab-a273-4253b8b321eb")
        .setName("test")
        .setRule(AttributeRuleTypeEnum.forNumber(AttributeRuleTypeEnum.ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF_VALUE))
        .addAllValues(Arrays.asList("test1", "test2")).build();

        CreateAttributeResponse resp = sdk.getServices().attributes().createAttribute(request).get();

        Attribute attribute = resp.getAttribute();

    }
}
