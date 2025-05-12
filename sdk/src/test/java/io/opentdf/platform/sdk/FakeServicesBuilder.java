package io.opentdf.platform.sdk;

import io.opentdf.platform.authorization.AuthorizationServiceClient;
import io.opentdf.platform.policy.attributes.AttributesServiceClient;
import io.opentdf.platform.policy.kasregistry.KeyAccessServerRegistryServiceClient;
import io.opentdf.platform.policy.namespaces.NamespaceServiceClient;
import io.opentdf.platform.policy.resourcemapping.ResourceMappingServiceClient;
import io.opentdf.platform.policy.subjectmapping.SubjectMappingServiceClient;

public class FakeServicesBuilder {
    private AuthorizationServiceClient authorizationService;
    private AttributesServiceClient attributesService;
    private NamespaceServiceClient namespaceService;
    private SubjectMappingServiceClient subjectMappingService;
    private ResourceMappingServiceClient resourceMappingService;
    private KeyAccessServerRegistryServiceClient keyAccessServerRegistryServiceFutureStub;
    private SDK.KAS kas;

    public FakeServicesBuilder setAuthorizationService(AuthorizationServiceClient authorizationService) {
        this.authorizationService = authorizationService;
        return this;
    }

    public FakeServicesBuilder setAttributesService(AttributesServiceClient attributesService) {
        this.attributesService = attributesService;
        return this;
    }

    public FakeServicesBuilder setNamespaceService(NamespaceServiceClient namespaceService) {
        this.namespaceService = namespaceService;
        return this;
    }

    public FakeServicesBuilder setSubjectMappingService(SubjectMappingServiceClient subjectMappingService) {
        this.subjectMappingService = subjectMappingService;
        return this;
    }

    public FakeServicesBuilder setResourceMappingService(ResourceMappingServiceClient resourceMappingService) {
        this.resourceMappingService = resourceMappingService;
        return this;
    }

    public FakeServicesBuilder setKeyAccessServerRegistryService(KeyAccessServerRegistryServiceClient keyAccessServerRegistryServiceFutureStub) {
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