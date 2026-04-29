package io.opentdf.platform.sdk;

import static org.junit.jupiter.api.Assertions.*;

import io.opentdf.platform.authorization.v2.Resource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class ResourcesTest {

    @Test
    void forAttributeValues_single() {
        String fqn = "https://example.com/attr/department/value/finance";
        Resource r = Resources.forAttributeValues(fqn);

        assertEquals(Resource.ResourceCase.ATTRIBUTE_VALUES, r.getResourceCase());
        assertEquals(1, r.getAttributeValues().getFqnsCount());
        assertEquals(fqn, r.getAttributeValues().getFqns(0));
    }

    @Test
    void forAttributeValues_multiple() {
        String fqn1 = "https://example.com/attr/department/value/finance";
        String fqn2 = "https://example.com/attr/level/value/public";
        Resource r = Resources.forAttributeValues(fqn1, fqn2);

        assertEquals(Resource.ResourceCase.ATTRIBUTE_VALUES, r.getResourceCase());
        assertEquals(2, r.getAttributeValues().getFqnsCount());
        assertEquals(fqn1, r.getAttributeValues().getFqns(0));
        assertEquals(fqn2, r.getAttributeValues().getFqns(1));
    }

    @Test
    void forAttributeValues_emptyStringFqn() {
        Resource r = Resources.forAttributeValues("");

        assertEquals(Resource.ResourceCase.ATTRIBUTE_VALUES, r.getResourceCase());
        assertEquals(1, r.getAttributeValues().getFqnsCount());
        assertEquals("", r.getAttributeValues().getFqns(0));
    }

    @Test
    void forAttributeValues_emptyArrayThrows() {
        assertThrows(IllegalArgumentException.class, () -> Resources.forAttributeValues());
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://example.com/attr/department/value/finance", ""})
    void forRegisteredResourceValueFqn(String fqn) {
        Resource r = Resources.forRegisteredResourceValueFqn(fqn);

        assertEquals(Resource.ResourceCase.REGISTERED_RESOURCE_VALUE_FQN, r.getResourceCase());
        assertEquals(fqn, r.getRegisteredResourceValueFqn());
    }

    @Test
    void nullInputsThrow() {
        assertThrows(NullPointerException.class, () -> Resources.forAttributeValues((String[]) null));
        assertThrows(NullPointerException.class, () -> Resources.forAttributeValues("valid", null));
        assertThrows(NullPointerException.class, () -> Resources.forRegisteredResourceValueFqn(null));
    }
}
