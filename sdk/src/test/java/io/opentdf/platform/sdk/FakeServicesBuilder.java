package io.opentdf.platform.sdk;

import io.opentdf.platform.authorization.AuthorizationServiceClientInterface;
import io.opentdf.platform.policy.attributes.AttributesServiceClientInterface;
import io.opentdf.platform.policy.kasregistry.KeyAccessServerRegistryServiceClientInterface;
import io.opentdf.platform.policy.namespaces.NamespaceServiceClientInterface;
import io.opentdf.platform.policy.resourcemapping.ResourceMappingServiceClientInterface;
import io.opentdf.platform.policy.subjectmapping.SubjectMappingServiceClientInterface;
import io.opentdf.platform.wellknownconfiguration.WellKnownServiceClientInterface;

public class FakeServicesBuilder {
    private AuthorizationServiceClientInterface authorizationService;
    private AttributesServiceClientInterface attributesService;
    private NamespaceServiceClientInterface namespaceService;
    private SubjectMappingServiceClientInterface subjectMappingService;
    private ResourceMappingServiceClientInterface resourceMappingService;
    private KeyAccessServerRegistryServiceClientInterface keyAccessServerRegistryServiceFutureStub;
    private WellKnownServiceClientInterface wellKnownServiceClient;
    private SDK.KAS kas;

    public FakeServicesBuilder setAuthorizationService(AuthorizationServiceClientInterface authorizationService) {
        this.authorizationService = authorizationService;
        return this;
    }

    public FakeServicesBuilder setAttributesService(AttributesServiceClientInterface attributesService) {
        this.attributesService = attributesService;
        return this;
    }

    public FakeServicesBuilder setNamespaceService(NamespaceServiceClientInterface namespaceService) {
        this.namespaceService = namespaceService;
        return this;
    }

    public FakeServicesBuilder setSubjectMappingService(SubjectMappingServiceClientInterface subjectMappingService) {
        this.subjectMappingService = subjectMappingService;
        return this;
    }

    public FakeServicesBuilder setResourceMappingService(ResourceMappingServiceClientInterface resourceMappingService) {
        this.resourceMappingService = resourceMappingService;
        return this;
    }

    public FakeServicesBuilder setWellknownService(WellKnownServiceClientInterface wellKnownServiceClient) {
        this.wellKnownServiceClient = wellKnownServiceClient;
        return this;
    }

    public FakeServicesBuilder setKeyAccessServerRegistryService(KeyAccessServerRegistryServiceClientInterface keyAccessServerRegistryServiceFutureStub) {
        this.keyAccessServerRegistryServiceFutureStub = keyAccessServerRegistryServiceFutureStub;
        return this;
    }

    public FakeServicesBuilder setKas(SDK.KAS kas) {
        this.kas = kas;
        return this;
    }

    public FakeServices build() {
        return new FakeServices(authorizationService, attributesService, namespaceService, subjectMappingService,
                resourceMappingService, keyAccessServerRegistryServiceFutureStub, wellKnownServiceClient, kas);
    }
}