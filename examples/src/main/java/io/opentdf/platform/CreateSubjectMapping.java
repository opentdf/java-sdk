package io.opentdf.platform;
import io.opentdf.platform.sdk.*;

import java.util.concurrent.ExecutionException;

import io.opentdf.platform.policy.subjectmapping.*;
import io.opentdf.platform.policy.SubjectMapping;
import io.opentdf.platform.policy.Action;

public class CreateSubjectMapping {
    public static void main(String[] args) throws ExecutionException, InterruptedException{

        String clientId = "opentdf";
        String clientSecret = "secret";
        String platformEndpoint = "localhost:8080";

        SDKBuilder builder = new SDKBuilder();
        SDK sdk = builder.platformEndpoint(platformEndpoint)
                .clientSecret(clientId, clientSecret).useInsecurePlaintextConnection(true)
                .build();

        CreateSubjectMappingRequest request = CreateSubjectMappingRequest.newBuilder()
        .setAttributeValueId("33c47777-f3b6-492d-bcd2-5329e0aab642")
        .addActions(Action.newBuilder().setStandard(Action.StandardAction.STANDARD_ACTION_DECRYPT))
        .setExistingSubjectConditionSetId("9009fde8-d22b-4dfb-a456-f9ce6943244a")
        .build();

        CreateSubjectMappingResponse resp = sdk.getServices().subjectMappings().createSubjectMapping(request).get();

        SubjectMapping sm = resp.getSubjectMapping();

        System.out.println(sm.getId());
    }
}