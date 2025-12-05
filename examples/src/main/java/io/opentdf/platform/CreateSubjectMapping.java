package io.opentdf.platform;

import com.connectrpc.ResponseMessageKt;
import io.opentdf.platform.policy.Action;
import io.opentdf.platform.policy.Attribute;
import io.opentdf.platform.policy.AttributeRuleTypeEnum;
import io.opentdf.platform.policy.Condition;
import io.opentdf.platform.policy.ConditionBooleanTypeEnum;
import io.opentdf.platform.policy.ConditionGroup;
import io.opentdf.platform.policy.Namespace;
import io.opentdf.platform.policy.SubjectConditionSet;
import io.opentdf.platform.policy.SubjectMapping;
import io.opentdf.platform.policy.SubjectMappingOperatorEnum;
import io.opentdf.platform.policy.SubjectSet;
import io.opentdf.platform.policy.attributes.CreateAttributeRequest;
import io.opentdf.platform.policy.attributes.CreateAttributeResponse;
import io.opentdf.platform.policy.attributes.GetAttributeRequest;
import io.opentdf.platform.policy.namespaces.GetNamespaceRequest;
import io.opentdf.platform.policy.subjectmapping.CreateSubjectConditionSetRequest;
import io.opentdf.platform.policy.subjectmapping.CreateSubjectConditionSetResponse;
import io.opentdf.platform.policy.subjectmapping.CreateSubjectMappingRequest;
import io.opentdf.platform.policy.subjectmapping.CreateSubjectMappingResponse;
import io.opentdf.platform.policy.subjectmapping.SubjectConditionSetCreate;
import io.opentdf.platform.sdk.SDK;
import io.opentdf.platform.sdk.SDKBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Arrays;
import java.util.Collections;

public class CreateSubjectMapping {

  private static final Logger logger = LogManager.getLogger(CreateSubjectMapping.class);

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

      Namespace namespace;
      String namespaceName = "mynamespace.com";

      try {
        namespace =
            ResponseMessageKt.getOrThrow(
                    sdk.getServices()
                        .namespaces()
                        .getNamespaceBlocking(
                            GetNamespaceRequest.newBuilder()
                                .setFqn("https://" + namespaceName)
                                .build(),
                            Collections.emptyMap())
                        .execute())
                .getNamespace();
      } catch (Exception e) {
        logger.error("Namespace '{}' not found", namespaceName);
        throw e;
      }

      Attribute attribute;
      String attributeName = "test-attribute";
      String attributeFqn = namespace.getFqn() + "/attr/" + attributeName;

      try {
        logger.info("Attempting to retrieve attribute '{}'", attributeFqn);
        GetAttributeRequest getAttributeRequest =
            GetAttributeRequest.newBuilder().setFqn(attributeFqn).build();
        attribute =
            ResponseMessageKt.getOrThrow(
                    sdk.getServices()
                        .attributes()
                        .getAttributeBlocking(getAttributeRequest, Collections.emptyMap())
                        .execute())
                .getAttribute();
        logger.info("Found existing attribute with ID: {}", attribute.getId());
      } catch (Exception e) {
        logger.info("Attribute '{}' not found, creating it...", attributeFqn);
        CreateAttributeRequest attributeRequest =
            CreateAttributeRequest.newBuilder()
                .setNamespaceId(namespace.getId())
                .setName(attributeName)
                .setRule(
                    AttributeRuleTypeEnum.forNumber(
                        AttributeRuleTypeEnum.ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF_VALUE))
                .addAllValues(Arrays.asList("test1", "test2"))
                .build();
        CreateAttributeResponse attributeResponse =
            ResponseMessageKt.getOrThrow(
                sdk.getServices()
                    .attributes()
                    .createAttributeBlocking(attributeRequest, Collections.emptyMap())
                    .execute());
        attribute = attributeResponse.getAttribute();
        logger.info("Successfully created attribute with ID: {}", attribute.getId());
      }
      logger.info("Using attribute with FQN: {}", attribute.getFqn());

      logger.info("Creating subject condition set...");
      // Create Subject Condition Set
      CreateSubjectConditionSetRequest subjectConditionSetRequest =
          CreateSubjectConditionSetRequest.newBuilder()
              .setSubjectConditionSet(
                  SubjectConditionSetCreate.newBuilder()
                      .addSubjectSets(
                          SubjectSet.newBuilder()
                              .addConditionGroups(
                                  ConditionGroup.newBuilder()
                                      .setBooleanOperator(
                                          ConditionBooleanTypeEnum.CONDITION_BOOLEAN_TYPE_ENUM_AND)
                                      .addConditions(
                                          Condition.newBuilder()
                                              .setSubjectExternalSelectorValue(".myfield")
                                              .setOperator(
                                                  SubjectMappingOperatorEnum
                                                      .SUBJECT_MAPPING_OPERATOR_ENUM_IN)
                                              .addSubjectExternalValues("myvalue")))))
              .build();
      CreateSubjectConditionSetResponse subjectConditionSetResponse =
          ResponseMessageKt.getOrThrow(
              sdk.getServices()
                  .subjectMappings()
                  .createSubjectConditionSetBlocking(
                      subjectConditionSetRequest, Collections.emptyMap())
                  .execute());
      SubjectConditionSet subjectConditionSet =
          subjectConditionSetResponse.getSubjectConditionSet();
      logger.info(
          "Successfully created subject condition set with ID: {}", subjectConditionSet.getId());

      logger.info("Creating subject mapping...");
      // Create Subject Mapping
      CreateSubjectMappingRequest request =
          CreateSubjectMappingRequest.newBuilder()
              .setAttributeValueId(attribute.getValues(0).getId())
              .addActions(Action.newBuilder().setName("read"))
              .setExistingSubjectConditionSetId(subjectConditionSet.getId())
              .build();
      CreateSubjectMappingResponse resp =
          ResponseMessageKt.getOrThrow(
              sdk.getServices()
                  .subjectMappings()
                  .createSubjectMappingBlocking(request, Collections.emptyMap())
                  .execute());

      SubjectMapping subjectMapping = resp.getSubjectMapping();

      logger.info("Successfully created subject mapping with ID: {}", subjectMapping.getId());
    } catch (Exception e) {
      logger.fatal("Failed to create subject mapping", e);
    }
  }
}
