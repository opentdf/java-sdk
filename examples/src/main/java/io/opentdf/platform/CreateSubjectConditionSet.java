package io.opentdf.platform;
import com.connectrpc.ResponseMessageKt;
import io.opentdf.platform.generated.policy.Condition;
import io.opentdf.platform.generated.policy.ConditionBooleanTypeEnum;
import io.opentdf.platform.generated.policy.ConditionGroup;
import io.opentdf.platform.generated.policy.SubjectConditionSet;
import io.opentdf.platform.generated.policy.SubjectMappingOperatorEnum;
import io.opentdf.platform.generated.policy.SubjectSet;
import io.opentdf.platform.generated.policy.subjectmapping.CreateSubjectConditionSetRequest;
import io.opentdf.platform.generated.policy.subjectmapping.CreateSubjectConditionSetResponse;
import io.opentdf.platform.generated.policy.subjectmapping.SubjectConditionSetCreate;
import io.opentdf.platform.sdk.*;

import java.util.Collections;
import java.util.concurrent.ExecutionException;


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

        CreateSubjectConditionSetResponse resp = ResponseMessageKt.getOrThrow(sdk.getServices().subjectMappings().createSubjectConditionSetBlocking(request, Collections.emptyMap()).execute());

        SubjectConditionSet scs = resp.getSubjectConditionSet();

        System.out.println(scs.getId());
    }
}
