package io.opentdf.platform;

import com.connectrpc.ResponseMessageKt;
import io.opentdf.platform.policy.Condition;
import io.opentdf.platform.policy.ConditionGroup;
import io.opentdf.platform.policy.SubjectConditionSet;
import io.opentdf.platform.policy.SubjectSet;
import static io.opentdf.platform.sdk.PolicyEnums.*;
import io.opentdf.platform.policy.subjectmapping.CreateSubjectConditionSetRequest;
import io.opentdf.platform.policy.subjectmapping.CreateSubjectConditionSetResponse;
import io.opentdf.platform.policy.subjectmapping.SubjectConditionSetCreate;
import io.opentdf.platform.sdk.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Collections;

public class CreateSubjectConditionSet {

  private static final Logger logger = LogManager.getLogger(CreateSubjectConditionSet.class);

  public static void main(String[] args) {

    String clientId = "opentdf";
    String clientSecret = "secret";
    String platformEndpoint = "localhost:8080";

    SDKBuilder builder = new SDKBuilder();

    try (SDK sdk =
        builder
            .platformEndpoint(platformEndpoint)
            .clientSecret(clientId, clientSecret)
            .useInsecurePlaintextConnection(true)
            .build()) {

      SubjectSet.Builder subjectSetBuilder =
          SubjectSet.newBuilder()
              .addConditionGroups(
                  ConditionGroup.newBuilder()
                      .setBooleanOperator(BOOLEAN_AND)
                      .addConditions(
                          Condition.newBuilder()
                              .setSubjectExternalSelectorValue(".myfield")
                              .setOperator(OPERATOR_IN)
                              .addSubjectExternalValues("myvalue")));

      CreateSubjectConditionSetRequest createSubjectConditionSetRequest =
          CreateSubjectConditionSetRequest.newBuilder()
              .setSubjectConditionSet(
                  SubjectConditionSetCreate.newBuilder().addSubjectSets(subjectSetBuilder))
              .build();

      CreateSubjectConditionSetResponse createSubjectConditionSetResponse =
          ResponseMessageKt.getOrThrow(
              sdk.getServices()
                  .subjectMappings()
                  .createSubjectConditionSetBlocking(
                      createSubjectConditionSetRequest, Collections.emptyMap())
                  .execute());

      SubjectConditionSet subjectConditionSet =
          createSubjectConditionSetResponse.getSubjectConditionSet();

      logger.info(
          "Successfully created subject condition set with ID: {}", subjectConditionSet.getId());

    } catch (Exception e) {
      logger.error("Failed to create subject condition set", e);
    }
  }
}
