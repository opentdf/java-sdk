package io.opentdf.platform;
import com.connectrpc.ResponseMessageKt;
import io.opentdf.platform.policy.SubjectMapping;
import io.opentdf.platform.policy.subjectmapping.ListSubjectMappingsRequest;
import io.opentdf.platform.policy.subjectmapping.ListSubjectMappingsResponse;
import io.opentdf.platform.sdk.*;

import java.util.Collections;
import java.util.concurrent.ExecutionException;

import java.util.List;

public class ListSubjectMappings {
    public static void main(String[] args) {

        String clientId = "opentdf";
        String clientSecret = "secret";
        String platformEndpoint = "localhost:8080";

        SDKBuilder builder = new SDKBuilder();
        SDK sdk = builder.platformEndpoint(platformEndpoint)
                .clientSecret(clientId, clientSecret).useInsecurePlaintextConnection(true)
                .build();
    
        ListSubjectMappingsRequest request = ListSubjectMappingsRequest.newBuilder().build();

        ListSubjectMappingsResponse resp = ResponseMessageKt.getOrThrow(sdk.getServices().subjectMappings().listSubjectMappingsBlocking(request, Collections.emptyMap()).execute());

        List<SubjectMapping> sms = resp.getSubjectMappingsList();

        System.out.println(sms.size());
        System.out.println(sms.get(0).getId());
    }
}
