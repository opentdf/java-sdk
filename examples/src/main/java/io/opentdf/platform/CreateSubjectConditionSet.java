package io.opentdf.platform;
import io.opentdf.platform.sdk.*;

import java.util.concurrent.ExecutionException;

import io.opentdf.platform.policy.subjectmapping.*;
import io.opentdf.platform.policy.SubjectMapping;
import io.opentdf.platform.policy.SubjectConditionSet;
import io.opentdf.platform.policy.SubjectSet;
import io.opentdf.platform.policy.ConditionGroup;
import io.opentdf.platform.policy.Condition;
import io.opentdf.platform.policy.ConditionBooleanTypeEnum;
import io.opentdf.platform.policy.SubjectMappingOperatorEnum;


public class CreateSubjectConditionSet {
    public static void main(String[] args) throws ExecutionException, InterruptedException{

        String clientId = "opentdf";
        String clientSecret = "secret";
        String platformEndpoint = "localhost:8080";

        SDKBuilder builder = new SDKBuilder();
        SDK sdk = builder.platformEndpoint(platformEndpoint)
                .clientSecret(clientId, clientSecret).useInsecurePlaintextConnection(true)
                .build();

        var subjectset = SubjectSet.newBuilder().addConditionGroups(ConditionGroup.newBuilder()
        .setBooleanOperator(ConditionBooleanTypeEnum.CONDITION_BOOLEAN_TYPE_ENUM_AND)
        .addConditions(Condition.newBuilder()
        .setSubjectExternalSelectorValue(".myfield")
        .setOperator(SubjectMappingOperatorEnum.SUBJECT_MAPPING_OPERATOR_ENUM_IN)
        .addSubjectExternalValues("myvalue")
        ));

        CreateSubjectConditionSetRequest request = CreateSubjectConditionSetRequest.newBuilder()
        .setSubjectConditionSet(
            SubjectConditionSetCreate.newBuilder().addSubjectSets(subjectset))
        .build();

        CreateSubjectConditionSetResponse resp = sdk.getServices().subjectMappings().createSubjectConditionSet(request).get();

        SubjectConditionSet scs = resp.getSubjectConditionSet();

        System.out.println(scs.getId());
    }
}
