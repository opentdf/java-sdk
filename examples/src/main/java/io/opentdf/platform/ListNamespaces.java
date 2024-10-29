package io.opentdf.platform;
import io.opentdf.platform.sdk.*;

import java.util.concurrent.ExecutionException;

import io.opentdf.platform.policy.namespaces.*;
import io.opentdf.platform.policy.Namespace;

public class ListNamespaces {
    public static void main(String[] args) throws ExecutionException, InterruptedException{

        String clientId = "opentdf";
        String clientSecret = "secret";
        String platformEndpoint = "localhost:8080";

        SDKBuilder builder = new SDKBuilder();
        SDK sdk = builder.platformEndpoint(platformEndpoint)
                .clientSecret(clientId, clientSecret).useInsecurePlaintextConnection(true)
                .build();

        ListNamespacesRequest request = ListNamespacesRequest.newBuilder().build();

        ListNamespacesResponse resp = sdk.getServices().namespaces().listNamespaces(request).get();

        java.util.List<Namespace> namespaces = resp.getNamespacesList();
    }
}
