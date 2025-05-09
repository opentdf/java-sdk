package io.opentdf.platform;
import com.connectrpc.ResponseMessageKt;
import io.opentdf.platform.policy.Namespace;
import io.opentdf.platform.policy.namespaces.ListNamespacesRequest;
import io.opentdf.platform.policy.namespaces.ListNamespacesResponse;
import io.opentdf.platform.sdk.*;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutionException;

public class ListNamespaces {
    public static void main(String[] args) {

        String clientId = "opentdf";
        String clientSecret = "secret";
        String platformEndpoint = "localhost:8080";

        SDKBuilder builder = new SDKBuilder();
        SDK sdk = builder.platformEndpoint(platformEndpoint)
                .clientSecret(clientId, clientSecret).useInsecurePlaintextConnection(true)
                .build();

        ListNamespacesRequest request = ListNamespacesRequest.newBuilder().build();

        ListNamespacesResponse resp = ResponseMessageKt.getOrThrow(sdk.getServices().namespaces().listNamespacesBlocking(request, Collections.emptyMap()).execute());

        List<Namespace> namespaces = resp.getNamespacesList();
    }
}
