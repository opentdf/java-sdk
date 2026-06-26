package io.opentdf.platform.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.opentdf.platform.common.ActiveStateEnum;
import io.opentdf.platform.policy.AttributeRuleTypeEnum;
import io.opentdf.platform.policy.ConditionBooleanTypeEnum;
import io.opentdf.platform.policy.SubjectMappingOperatorEnum;
import org.junit.jupiter.api.Test;

class PolicyEnumsTest {

    @Test
    void operatorConstants() {
        assertEquals(
                SubjectMappingOperatorEnum.SUBJECT_MAPPING_OPERATOR_ENUM_IN,
                PolicyEnums.OPERATOR_IN);
        assertEquals(
                SubjectMappingOperatorEnum.SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN,
                PolicyEnums.OPERATOR_NOT_IN);
        assertEquals(
                SubjectMappingOperatorEnum.SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS,
                PolicyEnums.OPERATOR_IN_CONTAINS);
    }

    @Test
    void booleanConstants() {
        assertEquals(
                ConditionBooleanTypeEnum.CONDITION_BOOLEAN_TYPE_ENUM_AND,
                PolicyEnums.BOOLEAN_AND);
        assertEquals(
                ConditionBooleanTypeEnum.CONDITION_BOOLEAN_TYPE_ENUM_OR,
                PolicyEnums.BOOLEAN_OR);
    }

    @Test
    void ruleConstants() {
        assertEquals(
                AttributeRuleTypeEnum.ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
                PolicyEnums.RULE_ALL_OF);
        assertEquals(
                AttributeRuleTypeEnum.ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
                PolicyEnums.RULE_ANY_OF);
        assertEquals(
                AttributeRuleTypeEnum.ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
                PolicyEnums.RULE_HIERARCHY);
    }

    @Test
    void stateConstants() {
        assertEquals(
                ActiveStateEnum.ACTIVE_STATE_ENUM_ACTIVE,
                PolicyEnums.STATE_ACTIVE);
        assertEquals(
                ActiveStateEnum.ACTIVE_STATE_ENUM_INACTIVE,
                PolicyEnums.STATE_INACTIVE);
        assertEquals(
                ActiveStateEnum.ACTIVE_STATE_ENUM_ANY,
                PolicyEnums.STATE_ANY);
    }
}
