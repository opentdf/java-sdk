package io.opentdf.platform.sdk;

import io.opentdf.platform.authorization.AuthorizationServiceClientInterface;
import io.opentdf.platform.policy.attributes.AttributesServiceClientInterface;
import io.opentdf.platform.policy.kasregistry.KeyAccessServerRegistryServiceClientInterface;
import io.opentdf.platform.policy.namespaces.NamespaceServiceClientInterface;
import io.opentdf.platform.policy.resourcemapping.ResourceMappingServiceClientInterface;
import io.opentdf.platform.policy.subjectmapping.SubjectMappingServiceClientInterface;
import io.opentdf.platform.wellknownconfiguration.WellKnownServiceClientInterface;

import java.util.Objects;

public class FakeServices implements SDK.Services {

    private final AuthorizationServiceClientInterface authorizationService;
    private final AttributesServiceClientInterface attributesService;
    private final NamespaceServiceClientInterface namespaceService;
    private final SubjectMappingServiceClientInterface subjectMappingService;
    private final ResourceMappingServiceClientInterface resourceMappingService;
    private final KeyAccessServerRegistryServiceClientInterface keyAccessServerRegistryServiceFutureStub;
    private final WellKnownServiceClientInterface wellKnownService;
    private final SDK.KAS kas;

    public FakeServices(
            AuthorizationServiceClientInterface authorizationService,
            AttributesServiceClientInterface attributesService,
            NamespaceServiceClientInterface namespaceService,
            SubjectMappingServiceClientInterface subjectMappingService,
            ResourceMappingServiceClientInterface resourceMappingService,
            KeyAccessServerRegistryServiceClientInterface keyAccessServerRegistryServiceFutureStub,
            WellKnownServiceClientInterface wellKnownServiceClient,
            SDK.KAS kas) {
        this.authorizationService = authorizationService;
        this.attributesService = attributesService;
        this.namespaceService = namespaceService;
        this.subjectMappingService = subjectMappingService;
        this.resourceMappingService = resourceMappingService;
        this.keyAccessServerRegistryServiceFutureStub = keyAccessServerRegistryServiceFutureStub;
        this.wellKnownService = wellKnownServiceClient;
        this.kas = kas;
    }

    @Override
    public AuthorizationServiceClientInterface authorization() {
        return Objects.requireNonNull(authorizationService);
    }

    @Override
    public AttributesServiceClientInterface attributes() {
        return Objects.requireNonNull(attributesService);
    }

    @Override
    public NamespaceServiceClientInterface namespaces() {
        return Objects.requireNonNull(namespaceService);
    }

    @Override
    public SubjectMappingServiceClientInterface subjectMappings() {
        return Objects.requireNonNull(subjectMappingService);
    }

    @Override
    public ResourceMappingServiceClientInterface resourceMappings() {
        return Objects.requireNonNull(resourceMappingService);
    }

    @Override
    public KeyAccessServerRegistryServiceClientInterface kasRegistry() {
        return Objects.requireNonNull(keyAccessServerRegistryServiceFutureStub);
    }

    @Override
    public WellKnownServiceClientInterface wellknown() {
        return Objects.requireNonNull(wellKnownService);
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
