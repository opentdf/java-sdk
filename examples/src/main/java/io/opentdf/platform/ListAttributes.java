package io.opentdf.platform;
import com.connectrpc.ResponseMessageKt;
import io.opentdf.platform.generated.policy.Attribute;
import io.opentdf.platform.generated.policy.attributes.ListAttributesRequest;
import io.opentdf.platform.generated.policy.attributes.ListAttributesResponse;
import io.opentdf.platform.sdk.*;

import java.util.Collections;
import java.util.concurrent.ExecutionException;

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

        ListAttributesResponse resp = ResponseMessageKt.getOrThrow(sdk.getServices().attributes().listAttributesBlocking(request, Collections.emptyMap()).execute());

        List<Attribute> attributes = resp.getAttributesList();

        System.out.println(resp.getAttributesCount());
    }
}
