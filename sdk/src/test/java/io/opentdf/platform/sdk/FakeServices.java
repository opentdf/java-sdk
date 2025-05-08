package io.opentdf.platform.sdk;

import io.opentdf.platform.authorization.AuthorizationServiceGrpc;
import io.opentdf.platform.policy.attributes.AttributesServiceGrpc;
import io.opentdf.platform.policy.kasregistry.KeyAccessServerRegistryServiceGrpc;
import io.opentdf.platform.policy.namespaces.NamespaceServiceGrpc;
import io.opentdf.platform.policy.resourcemapping.ResourceMappingServiceGrpc;
import io.opentdf.platform.policy.subjectmapping.SubjectMappingServiceGrpc;

import java.util.Objects;

public class FakeServices implements SDK.Services {

    private final AuthorizationServiceGrpc.AuthorizationServiceFutureStub authorizationService;
    private final AttributesServiceGrpc.AttributesServiceFutureStub attributesService;
    private final NamespaceServiceGrpc.NamespaceServiceFutureStub namespaceService;
    private final SubjectMappingServiceGrpc.SubjectMappingServiceFutureStub subjectMappingService;
    private final ResourceMappingServiceGrpc.ResourceMappingServiceFutureStub resourceMappingService;
    private final KeyAccessServerRegistryServiceGrpc.KeyAccessServerRegistryServiceFutureStub keyAccessServerRegistryServiceFutureStub;
    private final SDK.KAS kas;

    public FakeServices(
            AuthorizationServiceGrpc.AuthorizationServiceFutureStub authorizationService,
            AttributesServiceGrpc.AttributesServiceFutureStub attributesService,
            NamespaceServiceGrpc.NamespaceServiceFutureStub namespaceService,
            SubjectMappingServiceGrpc.SubjectMappingServiceFutureStub subjectMappingService,
            ResourceMappingServiceGrpc.ResourceMappingServiceFutureStub resourceMappingService,
            KeyAccessServerRegistryServiceGrpc.KeyAccessServerRegistryServiceFutureStub keyAccessServerRegistryServiceFutureStub,
            SDK.KAS kas) {
        this.authorizationService = authorizationService;
        this.attributesService = attributesService;
        this.namespaceService = namespaceService;
        this.subjectMappingService = subjectMappingService;
        this.resourceMappingService = resourceMappingService;
        this.keyAccessServerRegistryServiceFutureStub = keyAccessServerRegistryServiceFutureStub;
        this.kas = kas;
    }

    @Override
    public AuthorizationServiceGrpc.AuthorizationServiceFutureStub authorization() {
        return Objects.requireNonNull(authorizationService);
    }

    @Override
    public AttributesServiceGrpc.AttributesServiceFutureStub attributes() {
        return Objects.requireNonNull(attributesService);
    }

    @Override
    public NamespaceServiceGrpc.NamespaceServiceFutureStub namespaces() {
        return Objects.requireNonNull(namespaceService);
    }

    @Override
    public SubjectMappingServiceGrpc.SubjectMappingServiceFutureStub subjectMappings() {
        return Objects.requireNonNull(subjectMappingService);
    }

    @Override
    public ResourceMappingServiceGrpc.ResourceMappingServiceFutureStub resourceMappings() {
        return Objects.requireNonNull(resourceMappingService);
    }

    @Override
    public KeyAccessServerRegistryServiceGrpc.KeyAccessServerRegistryServiceFutureStub kasRegistry() {
        return Objects.requireNonNull(keyAccessServerRegistryServiceFutureStub);
    }

    @Override
    public SDK.KAS kas() {
        return Objects.requireNonNull(kas);
    }

    @Override
    public void close() {
        // no-op for this fake stuff in tests
    }
}
