package io.opentdf.platform.sdk;

import io.opentdf.platform.authorization.AuthorizationServiceClient;
import io.opentdf.platform.policy.attributes.AttributesServiceClient;
import io.opentdf.platform.policy.kasregistry.KeyAccessServerRegistryServiceClient;
import io.opentdf.platform.policy.namespaces.NamespaceServiceClient;
import io.opentdf.platform.policy.resourcemapping.ResourceMappingServiceClient;
import io.opentdf.platform.policy.subjectmapping.SubjectMappingServiceClient;

import java.util.Objects;

public class FakeServices implements SDK.Services {

    private final AuthorizationServiceClient authorizationService;
    private final AttributesServiceClient attributesService;
    private final NamespaceServiceClient namespaceService;
    private final SubjectMappingServiceClient subjectMappingService;
    private final ResourceMappingServiceClient resourceMappingService;
    private final KeyAccessServerRegistryServiceClient keyAccessServerRegistryServiceFutureStub;
    private final SDK.KAS kas;

    public FakeServices(
            AuthorizationServiceClient authorizationService,
            AttributesServiceClient attributesService,
            NamespaceServiceClient namespaceService,
            SubjectMappingServiceClient subjectMappingService,
            ResourceMappingServiceClient resourceMappingService,
            KeyAccessServerRegistryServiceClient keyAccessServerRegistryServiceFutureStub,
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
    public AuthorizationServiceClient authorization() {
        return Objects.requireNonNull(authorizationService);
    }

    @Override
    public AttributesServiceClient attributes() {
        return Objects.requireNonNull(attributesService);
    }

    @Override
    public NamespaceServiceClient namespaces() {
        return Objects.requireNonNull(namespaceService);
    }

    @Override
    public SubjectMappingServiceClient subjectMappings() {
        return Objects.requireNonNull(subjectMappingService);
    }

    @Override
    public ResourceMappingServiceClient resourceMappings() {
        return Objects.requireNonNull(resourceMappingService);
    }

    @Override
    public KeyAccessServerRegistryServiceClient kasRegistry() {
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
