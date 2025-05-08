package io.opentdf.platform.sdk;

import io.opentdf.platform.authorization.AuthorizationServiceGrpc;
import io.opentdf.platform.policy.attributes.AttributesServiceGrpc;
import io.opentdf.platform.policy.kasregistry.KeyAccessServerRegistryServiceGrpc;
import io.opentdf.platform.policy.namespaces.NamespaceServiceGrpc;
import io.opentdf.platform.policy.resourcemapping.ResourceMappingServiceGrpc;
import io.opentdf.platform.policy.subjectmapping.SubjectMappingServiceGrpc;

public class FakeServicesBuilder {
    private AuthorizationServiceGrpc.AuthorizationServiceFutureStub authorizationService;
    private AttributesServiceGrpc.AttributesServiceFutureStub attributesService;
    private NamespaceServiceGrpc.NamespaceServiceFutureStub namespaceService;
    private SubjectMappingServiceGrpc.SubjectMappingServiceFutureStub subjectMappingService;
    private ResourceMappingServiceGrpc.ResourceMappingServiceFutureStub resourceMappingService;
    private KeyAccessServerRegistryServiceGrpc.KeyAccessServerRegistryServiceFutureStub keyAccessServerRegistryServiceFutureStub;
    private SDK.KAS kas;

    public FakeServicesBuilder setAuthorizationService(AuthorizationServiceGrpc.AuthorizationServiceFutureStub authorizationService) {
        this.authorizationService = authorizationService;
        return this;
    }

    public FakeServicesBuilder setAttributesService(AttributesServiceGrpc.AttributesServiceFutureStub attributesService) {
        this.attributesService = attributesService;
        return this;
    }

    public FakeServicesBuilder setNamespaceService(NamespaceServiceGrpc.NamespaceServiceFutureStub namespaceService) {
        this.namespaceService = namespaceService;
        return this;
    }

    public FakeServicesBuilder setSubjectMappingService(SubjectMappingServiceGrpc.SubjectMappingServiceFutureStub subjectMappingService) {
        this.subjectMappingService = subjectMappingService;
        return this;
    }

    public FakeServicesBuilder setResourceMappingService(ResourceMappingServiceGrpc.ResourceMappingServiceFutureStub resourceMappingService) {
        this.resourceMappingService = resourceMappingService;
        return this;
    }

    public FakeServicesBuilder setKeyAccessServerRegistryService(KeyAccessServerRegistryServiceGrpc.KeyAccessServerRegistryServiceFutureStub keyAccessServerRegistryServiceFutureStub) {
        this.keyAccessServerRegistryServiceFutureStub = keyAccessServerRegistryServiceFutureStub;
        return this;
    }

    public FakeServicesBuilder setKas(SDK.KAS kas) {
        this.kas = kas;
        return this;
    }

    public FakeServices build() {
        return new FakeServices(authorizationService, attributesService, namespaceService, subjectMappingService, resourceMappingService, keyAccessServerRegistryServiceFutureStub, kas);
    }
}