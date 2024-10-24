package io.opentdf.platform;
import io.opentdf.platform.sdk.*;

import java.util.concurrent.ExecutionException;

import io.opentdf.platform.policy.subjectmapping.*;
import io.opentdf.platform.policy.SubjectMapping;

import java.util.List;

public class ListSubjectMappings {
    public static void main(String[] args) throws ExecutionException, InterruptedException{

        String clientId = "opentdf";
        String clientSecret = "secret";
        String platformEndpoint = "localhost:8080";

        SDKBuilder builder = new SDKBuilder();
        SDK sdk = builder.platformEndpoint(platformEndpoint)
                .clientSecret(clientId, clientSecret).useInsecurePlaintextConnection(true)
                .build();
    
        ListSubjectMappingsRequest request = ListSubjectMappingsRequest.newBuilder().build();

        ListSubjectMappingsResponse resp = sdk.getServices().subjectMappings().listSubjectMappings(request).get();

        List<SubjectMapping> sms = resp.getSubjectMappingsList();

        System.out.println(sms.size());
        System.out.println(sms.get(0).getId());
    }
}
