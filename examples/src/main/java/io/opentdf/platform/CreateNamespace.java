package io.opentdf.platform;
import io.opentdf.platform.sdk.*;

import java.util.concurrent.ExecutionException;

import io.opentdf.platform.policy.namespaces.*;

public class CreateNamespace {
    public static void main(String[] args) throws ExecutionException, InterruptedException{

        String clientId = "opentdf";
        String clientSecret = "secret";
        String platformEndpoint = "localhost:8080";

        SDKBuilder builder = new SDKBuilder();
        SDK sdk = builder.platformEndpoint(platformEndpoint)
                .clientSecret(clientId, clientSecret).useInsecurePlaintextConnection(true)
                .build();

        CreateNamespaceRequest request = CreateNamespaceRequest.newBuilder().setName("mynamespace.com").build();

        CreateNamespaceResponse resp = sdk.getServices().namespaces().createNamespace(request).get();

        System.out.println(resp.getNamespace().getName());
        
    }
}