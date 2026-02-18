package io.opentdf.platform.sdk;

import io.opentdf.platform.authorization.Entity;
import io.opentdf.platform.authorization.EntityEntitlements;
import io.opentdf.platform.authorization.GetEntitlementsResponse;
import io.opentdf.platform.authorization.AuthorizationServiceClientInterface;
import io.opentdf.platform.policy.Attribute;
import io.opentdf.platform.policy.PageResponse;
import io.opentdf.platform.policy.attributes.AttributesServiceClientInterface;
import io.opentdf.platform.policy.Value;
import io.opentdf.platform.policy.attributes.GetAttributeRequest;
import io.opentdf.platform.policy.attributes.GetAttributeResponse;
import io.opentdf.platform.policy.attributes.GetAttributeValuesByFqnsResponse;
import io.opentdf.platform.policy.attributes.ListAttributesRequest;
import io.opentdf.platform.policy.attributes.ListAttributesResponse;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DiscoveryTest {

    // Helper: build a minimal SDK wired with mock services.
    private SDK sdkWith(AttributesServiceClientInterface attrSvc,
                        AuthorizationServiceClientInterface authzSvc) {
        var services = new FakeServicesBuilder()
                .setAttributesService(attrSvc)
                .setAuthorizationService(authzSvc)
                .build();
        return new SDK(services, null, null, null, null, null);
    }

    // Helper: build a ListAttributesResponse with optional next_offset.
    private ListAttributesResponse listResponse(List<Attribute> attrs, int nextOffset) {
        var builder = ListAttributesResponse.newBuilder().addAllAttributes(attrs);
        if (nextOffset != 0) {
            builder.setPagination(PageResponse.newBuilder().setNextOffset(nextOffset).build());
        }
        return builder.build();
    }

    // Helper: build a GetAttributeValuesByFqns response containing exactly the given FQNs.
    private GetAttributeValuesByFqnsResponse fqnResponse(String... presentFqns) {
        var builder = GetAttributeValuesByFqnsResponse.newBuilder();
        for (String fqn : presentFqns) {
            builder.putFqnAttributeValues(fqn,
                    GetAttributeValuesByFqnsResponse.AttributeAndValue.getDefaultInstance());
        }
        return builder.build();
    }

    // Helper: build a minimal Attribute proto with a given FQN.
    private Attribute attr(String fqn) {
        return Attribute.newBuilder().setFqn(fqn).build();
    }

    // --- listAttributes ---

    @Test
    void listAttributes_emptyResult() {
        var attrSvc = mock(AttributesServiceClientInterface.class);
        when(attrSvc.listAttributesBlocking(any(), any()))
                .thenReturn(TestUtil.successfulUnaryCall(listResponse(Collections.emptyList(), 0)));

        var sdk = sdkWith(attrSvc, null);
        List<Attribute> result = sdk.listAttributes();
        assertThat(result).isEmpty();
    }

    @Test
    void listAttributes_singlePage() {
        var expected = List.of(
                attr("https://example.com/attr/level/value/high"),
                attr("https://example.com/attr/level/value/low"));
        var attrSvc = mock(AttributesServiceClientInterface.class);
        when(attrSvc.listAttributesBlocking(any(), any()))
                .thenReturn(TestUtil.successfulUnaryCall(listResponse(expected, 0)));

        var sdk = sdkWith(attrSvc, null);
        assertThat(sdk.listAttributes()).containsExactlyElementsOf(expected);
    }

    @Test
    void listAttributes_multiPage() {
        var page1 = List.of(attr("https://example.com/attr/a/value/1"));
        var page2 = List.of(attr("https://example.com/attr/b/value/2"));

        var attrSvc = mock(AttributesServiceClientInterface.class);
        var callCount = new AtomicInteger(0);
        when(attrSvc.listAttributesBlocking(any(), any())).thenAnswer(invocation -> {
            int call = callCount.getAndIncrement();
            if (call == 0) {
                return TestUtil.successfulUnaryCall(listResponse(page1, 1));
            }
            return TestUtil.successfulUnaryCall(listResponse(page2, 0));
        });

        var sdk = sdkWith(attrSvc, null);
        var result = sdk.listAttributes();
        assertThat(callCount.get()).as("should have paginated twice").isEqualTo(2);
        var expected = new ArrayList<>(page1);
        expected.addAll(page2);
        assertThat(result).containsExactlyElementsOf(expected);
    }

    @Test
    void listAttributes_namespaceFilter() {
        var attrSvc = mock(AttributesServiceClientInterface.class);
        var capturedReq = new ListAttributesRequest[1];
        when(attrSvc.listAttributesBlocking(any(), any())).thenAnswer(invocation -> {
            capturedReq[0] = (ListAttributesRequest) invocation.getArgument(0);
            return TestUtil.successfulUnaryCall(listResponse(Collections.emptyList(), 0));
        });

        var sdk = sdkWith(attrSvc, null);
        sdk.listAttributes("my-namespace");
        assertThat(capturedReq[0].getNamespace()).isEqualTo("my-namespace");
    }

    @Test
    void listAttributes_pageLimitExceeded() {
        var attrSvc = mock(AttributesServiceClientInterface.class);
        // Always return a non-zero next_offset to simulate a runaway server.
        when(attrSvc.listAttributesBlocking(any(), any()))
                .thenReturn(TestUtil.successfulUnaryCall(
                        listResponse(List.of(attr("https://example.com/attr/a/value/1")), 1)));

        var sdk = sdkWith(attrSvc, null);
        assertThatThrownBy(sdk::listAttributes)
                .isInstanceOf(SDKException.class)
                .hasMessageContaining("exceeded maximum page limit");
    }

    // --- validateAttributes ---

    @Test
    void validateAttributes_nullInput_noOp() {
        var sdk = sdkWith(null, null);
        // Should not throw and must not call any service.
        sdk.validateAttributes(null);
    }

    @Test
    void validateAttributes_emptyInput_noOp() {
        var sdk = sdkWith(null, null);
        sdk.validateAttributes(Collections.emptyList());
    }

    @Test
    void validateAttributes_allFound() {
        var fqns = List.of(
                "https://example.com/attr/level/value/high",
                "https://example.com/attr/type/value/secret");
        var attrSvc = mock(AttributesServiceClientInterface.class);
        when(attrSvc.getAttributeValuesByFqnsBlocking(any(), any()))
                .thenReturn(TestUtil.successfulUnaryCall(fqnResponse(fqns.toArray(new String[0]))));

        var sdk = sdkWith(attrSvc, null);
        // Should complete without exception.
        sdk.validateAttributes(fqns);
    }

    @Test
    void validateAttributes_someMissing() {
        var fqns = List.of(
                "https://example.com/attr/level/value/high",
                "https://example.com/attr/type/value/missing");
        var attrSvc = mock(AttributesServiceClientInterface.class);
        // Only return the first FQN.
        when(attrSvc.getAttributeValuesByFqnsBlocking(any(), any()))
                .thenReturn(TestUtil.successfulUnaryCall(fqnResponse(fqns.get(0))));

        var sdk = sdkWith(attrSvc, null);
        assertThatThrownBy(() -> sdk.validateAttributes(fqns))
                .isInstanceOf(SDK.AttributeNotFoundException.class)
                .hasMessageContaining("https://example.com/attr/type/value/missing");
    }

    @Test
    void validateAttributes_allMissing() {
        var fqns = List.of(
                "https://example.com/attr/a/value/x",
                "https://example.com/attr/b/value/y");
        var attrSvc = mock(AttributesServiceClientInterface.class);
        when(attrSvc.getAttributeValuesByFqnsBlocking(any(), any()))
                .thenReturn(TestUtil.successfulUnaryCall(fqnResponse()));

        var sdk = sdkWith(attrSvc, null);
        assertThatThrownBy(() -> sdk.validateAttributes(fqns))
                .isInstanceOf(SDK.AttributeNotFoundException.class);
    }

    @Test
    void validateAttributes_tooManyFqns() {
        var fqns = new ArrayList<String>();
        for (int i = 0; i <= 250; i++) {
            fqns.add("https://example.com/attr/level/value/v" + i);
        }
        var sdk = sdkWith(null, null);
        assertThatThrownBy(() -> sdk.validateAttributes(fqns))
                .isInstanceOf(SDKException.class)
                .hasMessageContaining("too many attribute FQNs");
    }

    @Test
    void validateAttributes_invalidFqnFormat() {
        var sdk = sdkWith(null, null);
        assertThatThrownBy(() -> sdk.validateAttributes(List.of("not-a-valid-fqn")))
                .isInstanceOf(SDKException.class)
                .hasMessageContaining("invalid attribute value FQN");
    }

    // --- getEntityAttributes ---

    @Test
    void getEntityAttributes_nullEntity() {
        var sdk = sdkWith(null, null);
        assertThatThrownBy(() -> sdk.getEntityAttributes(null))
                .isInstanceOf(SDKException.class)
                .hasMessageContaining("entity must not be null");
    }

    @Test
    void getEntityAttributes_found() {
        var expectedFqns = List.of(
                "https://example.com/attr/clearance/value/secret",
                "https://example.com/attr/country/value/us");
        var authzSvc = mock(AuthorizationServiceClientInterface.class);
        when(authzSvc.getEntitlementsBlocking(any(), any())).thenReturn(
                TestUtil.successfulUnaryCall(GetEntitlementsResponse.newBuilder()
                        .addEntitlements(EntityEntitlements.newBuilder()
                                .setEntityId("e1")
                                .addAllAttributeValueFqns(expectedFqns)
                                .build())
                        .build()));

        var sdk = sdkWith(null, authzSvc);
        var entity = Entity.newBuilder().setId("e1").setEmailAddress("alice@example.com").build();
        assertThat(sdk.getEntityAttributes(entity)).containsExactlyElementsOf(expectedFqns);
    }

    @Test
    void getEntityAttributes_noEntitlements() {
        var authzSvc = mock(AuthorizationServiceClientInterface.class);
        when(authzSvc.getEntitlementsBlocking(any(), any())).thenReturn(
                TestUtil.successfulUnaryCall(GetEntitlementsResponse.newBuilder().build()));

        var sdk = sdkWith(null, authzSvc);
        var entity = Entity.newBuilder().setId("e1").setClientId("my-service").build();
        assertThat(sdk.getEntityAttributes(entity)).isEmpty();
    }

    @Test
    void getEntityAttributes_idMismatch() {
        // Server returns entitlements for a different entity ID than requested.
        var authzSvc = mock(AuthorizationServiceClientInterface.class);
        when(authzSvc.getEntitlementsBlocking(any(), any())).thenReturn(
                TestUtil.successfulUnaryCall(GetEntitlementsResponse.newBuilder()
                        .addEntitlements(EntityEntitlements.newBuilder()
                                .setEntityId("other-entity")
                                .addAttributeValueFqns("https://example.com/attr/a/value/x")
                                .build())
                        .build()));

        var sdk = sdkWith(null, authzSvc);
        var entity = Entity.newBuilder().setId("e1").setEmailAddress("alice@example.com").build();
        assertThat(sdk.getEntityAttributes(entity))
                .as("should return empty when no entitlement matches the requested entity ID")
                .isEmpty();
    }

    // --- validateAttributeExists ---

    @Test
    void validateAttributeExists_validAndExists() {
        var fqn = "https://example.com/attr/level/value/high";
        var attrSvc = mock(AttributesServiceClientInterface.class);
        when(attrSvc.getAttributeValuesByFqnsBlocking(any(), any()))
                .thenReturn(TestUtil.successfulUnaryCall(fqnResponse(fqn)));

        var sdk = sdkWith(attrSvc, null);
        // Should complete without exception.
        sdk.validateAttributeExists(fqn);
    }

    @Test
    void validateAttributeExists_validButMissing() {
        var fqn = "https://example.com/attr/level/value/nonexistent";
        var attrSvc = mock(AttributesServiceClientInterface.class);
        when(attrSvc.getAttributeValuesByFqnsBlocking(any(), any()))
                .thenReturn(TestUtil.successfulUnaryCall(fqnResponse()));

        var sdk = sdkWith(attrSvc, null);
        assertThatThrownBy(() -> sdk.validateAttributeExists(fqn))
                .isInstanceOf(SDK.AttributeNotFoundException.class);
    }

    @Test
    void validateAttributeExists_invalidFormat() {
        var sdk = sdkWith(null, null);
        assertThatThrownBy(() -> sdk.validateAttributeExists("bad-fqn-format"))
                .isInstanceOf(SDKException.class)
                .hasMessageContaining("invalid attribute value FQN");
    }

    // --- validateAttributeValue ---

    // Helper: build a GetAttributeResponse with the given enumerated values.
    private GetAttributeResponse attrResponse(String... values) {
        var attrBuilder = Attribute.newBuilder();
        for (String v : values) {
            attrBuilder.addValues(Value.newBuilder().setValue(v).build());
        }
        return GetAttributeResponse.newBuilder().setAttribute(attrBuilder.build()).build();
    }

    @Test
    void validateAttributeValue_enumeratedMatch() {
        var attrFqn = "https://example.com/attr/clearance";
        var attrSvc = mock(AttributesServiceClientInterface.class);
        when(attrSvc.getAttributeBlocking(any(), any()))
                .thenReturn(TestUtil.successfulUnaryCall(attrResponse("low", "secret", "top-secret")));

        var sdk = sdkWith(attrSvc, null);
        // "secret" is in the list — should not throw.
        sdk.validateAttributeValue(attrFqn, "secret");
    }

    @Test
    void validateAttributeValue_enumeratedCaseInsensitive() {
        var attrFqn = "https://example.com/attr/clearance";
        var attrSvc = mock(AttributesServiceClientInterface.class);
        when(attrSvc.getAttributeBlocking(any(), any()))
                .thenReturn(TestUtil.successfulUnaryCall(attrResponse("Secret")));

        var sdk = sdkWith(attrSvc, null);
        sdk.validateAttributeValue(attrFqn, "SECRET");
    }

    @Test
    void validateAttributeValue_enumeratedNotFound() {
        var attrFqn = "https://example.com/attr/clearance";
        var attrSvc = mock(AttributesServiceClientInterface.class);
        when(attrSvc.getAttributeBlocking(any(), any()))
                .thenReturn(TestUtil.successfulUnaryCall(attrResponse("low", "secret")));

        var sdk = sdkWith(attrSvc, null);
        assertThatThrownBy(() -> sdk.validateAttributeValue(attrFqn, "top-secret"))
                .isInstanceOf(SDK.AttributeNotFoundException.class)
                .hasMessageContaining("top-secret");
    }

    @Test
    void validateAttributeValue_dynamic() {
        // Dynamic attribute: no pre-registered values — any string is valid.
        var attrFqn = "https://example.com/attr/tag";
        var attrSvc = mock(AttributesServiceClientInterface.class);
        when(attrSvc.getAttributeBlocking(any(), any()))
                .thenReturn(TestUtil.successfulUnaryCall(attrResponse())); // no values

        var sdk = sdkWith(attrSvc, null);
        sdk.validateAttributeValue(attrFqn, "anything-goes");
    }

    @Test
    void validateAttributeValue_attributeNotFound() {
        var attrFqn = "https://example.com/attr/nonexistent";
        var attrSvc = mock(AttributesServiceClientInterface.class);
        when(attrSvc.getAttributeBlocking(any(), any()))
                .thenThrow(new RuntimeException("not_found: attribute does not exist"));

        var sdk = sdkWith(attrSvc, null);
        assertThatThrownBy(() -> sdk.validateAttributeValue(attrFqn, "somevalue"))
                .isInstanceOf(SDK.AttributeNotFoundException.class);
    }

    @Test
    void validateAttributeValue_emptyValue() {
        var sdk = sdkWith(null, null);
        assertThatThrownBy(() -> sdk.validateAttributeValue("https://example.com/attr/clearance", ""))
                .isInstanceOf(SDKException.class)
                .hasMessageContaining("must not be empty");

        assertThatThrownBy(() -> sdk.validateAttributeValue("https://example.com/attr/clearance", null))
                .isInstanceOf(SDKException.class)
                .hasMessageContaining("must not be empty");
    }

    @Test
    void validateAttributeValue_invalidFqn() {
        // Passing a value FQN (contains /value/) should be rejected as an invalid attribute FQN.
        var sdk = sdkWith(null, null);
        assertThatThrownBy(() -> sdk.validateAttributeValue("https://example.com/attr/level/value/high", "high"))
                .isInstanceOf(SDKException.class)
                .hasMessageContaining("invalid attribute FQN");

        assertThatThrownBy(() -> sdk.validateAttributeValue("not-a-fqn", "somevalue"))
                .isInstanceOf(SDKException.class)
                .hasMessageContaining("invalid attribute FQN");
    }
}
