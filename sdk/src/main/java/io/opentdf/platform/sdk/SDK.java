package io.opentdf.platform.sdk;

import io.grpc.ManagedChannelBuilder;
import io.opentdf.platform.policy.attributes.AttributesServiceGrpc.AttributesServiceFutureStub;
import io.opentdf.platform.policy.namespaces.NamespaceServiceGrpc.NamespaceServiceFutureStub;
import io.opentdf.platform.policy.resourcemapping.ResourceMappingServiceGrpc.ResourceMappingServiceFutureStub;
import io.opentdf.platform.policy.subjectmapping.SubjectMappingServiceGrpc.SubjectMappingServiceFutureStub;

/**
 * The SDK class represents a software development kit for interacting with the opentdf platform. It
 * provides various services and stubs for making API calls to the opentdf platform.
 */
public class SDK {
    private final Services services;

    // TODO: add KAS
    public interface Services {
        AttributesServiceFutureStub attributes();
        NamespaceServiceFutureStub namespaces();
        SubjectMappingServiceFutureStub subjectMappings();
        ResourceMappingServiceFutureStub resourceMappings();
    }

    public SDK(Services services) {
        this.services = services;
    }


}