package io.opentdf.platform;
import io.opentdf.platform.sdk.*;

import java.util.concurrent.ExecutionException;

import io.opentdf.platform.authorization.*;

import java.util.List;

public class GetEntitlements {
    public static void main(String[] args) throws ExecutionException, InterruptedException{

        String clientId = "opentdf";
        String clientSecret = "secret";
        String platformEndpoint = "localhost:8080";

        SDKBuilder builder = new SDKBuilder();
        SDK sdk = builder.platformEndpoint(platformEndpoint)
                .clientSecret(clientId, clientSecret).useInsecurePlaintextConnection(true)
                .build();
    
        GetEntitlementsRequest request = GetEntitlementsRequest.newBuilder()
        .addEntities(Entity.newBuilder().setId("entity-1").setClientId("opentdf"))
        .build();

        GetEntitlementsResponse resp = sdk.getServices().authorization().getEntitlements(request).get();

        List<EntityEntitlements> entitlements = resp.getEntitlementsList();

        System.out.println(entitlements.get(0).getAttributeValueFqnsList());
    }
}
