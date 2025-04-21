package io.opentdf.platform;
import com.connectrpc.ResponseMessageKt;
import io.opentdf.platform.generated.policy.namespaces.CreateNamespaceRequest;
import io.opentdf.platform.generated.policy.namespaces.CreateNamespaceResponse;
import io.opentdf.platform.sdk.*;

import java.util.Collections;
import java.util.concurrent.ExecutionException;

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

        CreateNamespaceResponse resp = ResponseMessageKt.getOrThrow(sdk.getServices().namespaces().createNamespaceBlocking(request, Collections.emptyMap()).execute());

        System.out.println(resp.getNamespace().getName());
        
    }
}
