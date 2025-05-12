package io.opentdf.platform;
import com.connectrpc.ResponseMessageKt;
import io.opentdf.platform.authorization.Entity;
import io.opentdf.platform.authorization.EntityEntitlements;
import io.opentdf.platform.authorization.GetEntitlementsRequest;
import io.opentdf.platform.authorization.GetEntitlementsResponse;
import io.opentdf.platform.sdk.*;

import java.util.Collections;
import java.util.concurrent.ExecutionException;

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

        GetEntitlementsResponse resp = ResponseMessageKt.getOrThrow(sdk.getServices().authorization().getEntitlementsBlocking(request, Collections.emptyMap()).execute());

        List<EntityEntitlements> entitlements = resp.getEntitlementsList();

        System.out.println(entitlements.get(0).getAttributeValueFqnsList());
    }
}
