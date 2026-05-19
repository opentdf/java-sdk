package io.opentdf.platform.sdk;

import io.opentdf.platform.common.ActiveStateEnum;
import io.opentdf.platform.policy.AttributeRuleTypeEnum;
import io.opentdf.platform.policy.ConditionBooleanTypeEnum;
import io.opentdf.platform.policy.SubjectMappingOperatorEnum;

/**
 * Shorthand constants for commonly used policy enum values.
 *
 * <p>These aliases provide a more readable alternative to the verbose protobuf
 * enum names. Use them anywhere the corresponding enum type is accepted.
 *
 * <pre>{@code
 * // Before
 * Condition.newBuilder()
 *     .setOperator(SubjectMappingOperatorEnum.SUBJECT_MAPPING_OPERATOR_ENUM_IN);
 *
 * // After (with static import)
 * import static io.opentdf.platform.sdk.PolicyEnums.*;
 * Condition.newBuilder()
 *     .setOperator(OPERATOR_IN);
 * }</pre>
 */
final class PolicyEnums {

    private PolicyEnums() {}

    // --- Subject Mapping Operators ---

    public static final SubjectMappingOperatorEnum OPERATOR_IN =
            SubjectMappingOperatorEnum.SUBJECT_MAPPING_OPERATOR_ENUM_IN;

    public static final SubjectMappingOperatorEnum OPERATOR_NOT_IN =
            SubjectMappingOperatorEnum.SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN;

    public static final SubjectMappingOperatorEnum OPERATOR_IN_CONTAINS =
            SubjectMappingOperatorEnum.SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS;

    // --- Condition Boolean Types ---

    public static final ConditionBooleanTypeEnum BOOLEAN_AND =
            ConditionBooleanTypeEnum.CONDITION_BOOLEAN_TYPE_ENUM_AND;

    public static final ConditionBooleanTypeEnum BOOLEAN_OR =
            ConditionBooleanTypeEnum.CONDITION_BOOLEAN_TYPE_ENUM_OR;

    // --- Attribute Rule Types ---

    public static final AttributeRuleTypeEnum RULE_ALL_OF =
            AttributeRuleTypeEnum.ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF;

    public static final AttributeRuleTypeEnum RULE_ANY_OF =
            AttributeRuleTypeEnum.ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF;

    public static final AttributeRuleTypeEnum RULE_HIERARCHY =
            AttributeRuleTypeEnum.ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY;

    // --- Active States ---

    public static final ActiveStateEnum STATE_ACTIVE =
            ActiveStateEnum.ACTIVE_STATE_ENUM_ACTIVE;

    public static final ActiveStateEnum STATE_INACTIVE =
            ActiveStateEnum.ACTIVE_STATE_ENUM_INACTIVE;

    public static final ActiveStateEnum STATE_ANY =
            ActiveStateEnum.ACTIVE_STATE_ENUM_ANY;
}
