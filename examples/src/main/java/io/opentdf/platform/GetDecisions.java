package io.opentdf.platform;
import io.opentdf.platform.sdk.*;

import java.util.concurrent.ExecutionException;

import io.opentdf.platform.authorization.*;
import io.opentdf.platform.policy.Action;

import java.util.List;

public class GetDecisions {
    public static void main(String[] args) throws ExecutionException, InterruptedException{

        String clientId = "opentdf";
        String clientSecret = "secret";
        String platformEndpoint = "localhost:8080";

        SDKBuilder builder = new SDKBuilder();
        SDK sdk = builder.platformEndpoint(platformEndpoint)
                .clientSecret(clientId, clientSecret).useInsecurePlaintextConnection(true)
                .build();
    
        GetDecisionsRequest request = GetDecisionsRequest.newBuilder()
        .addDecisionRequests(DecisionRequest.newBuilder()
        .addEntityChains(EntityChain.newBuilder().setId("ec1").addEntities(Entity.newBuilder().setId("entity-1").setClientId("opentdf")))
        .addActions(Action.newBuilder().setStandard(Action.StandardAction.STANDARD_ACTION_DECRYPT))
        .addResourceAttributes(ResourceAttribute.newBuilder().setResourceAttributesId("resource-attribute-1")
            .addAttributeValueFqns("https://mynamespace.com/attr/test/value/test1"))
        ).build();

        GetDecisionsResponse resp = sdk.getServices().authorization().getDecisions(request).get();

        List<DecisionResponse> decisions = resp.getDecisionResponsesList();

        System.out.println(DecisionResponse.Decision.forNumber(decisions.get(0).getDecisionValue()));
    }
}