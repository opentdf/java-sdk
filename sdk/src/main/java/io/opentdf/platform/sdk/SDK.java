package io.opentdf.platform.sdk;

import io.grpc.ManagedChannel;
import io.opentdf.platform.authorization.AuthorizationServiceGrpc;
import io.opentdf.platform.authorization.AuthorizationServiceGrpc.AuthorizationServiceFutureStub;
import io.opentdf.platform.policy.attributes.AttributesServiceGrpc;
import io.opentdf.platform.policy.attributes.AttributesServiceGrpc.AttributesServiceFutureStub;
import io.opentdf.platform.policy.namespaces.NamespaceServiceGrpc;
import io.opentdf.platform.policy.namespaces.NamespaceServiceGrpc.NamespaceServiceFutureStub;
import io.opentdf.platform.policy.resourcemapping.ResourceMappingServiceGrpc;
import io.opentdf.platform.policy.resourcemapping.ResourceMappingServiceGrpc.ResourceMappingServiceFutureStub;
import io.opentdf.platform.policy.subjectmapping.SubjectMappingServiceGrpc;
import io.opentdf.platform.policy.subjectmapping.SubjectMappingServiceGrpc.SubjectMappingServiceFutureStub;
import io.opentdf.platform.sdk.nanotdf.NanoTDFType;

/**
 * The SDK class represents a software development kit for interacting with the opentdf platform. It
 * provides various services and stubs for making API calls to the opentdf platform.
 */
public class SDK implements AutoCloseable {
    private final Services services;

    @Override
    public void close() throws Exception {
        services.close();
    }

    public interface KAS extends AutoCloseable {
        String getPublicKey(Config.KASInfo kasInfo);
        String getKid(Config.KASInfo kasInfo);
        String getECPublicKey(Config.KASInfo kasInfo, NanoTDFType.ECCurve curve);
        byte[] unwrap(Manifest.KeyAccess keyAccess, String policy);
        byte[] unwrapNanoTDF(NanoTDFType.ECCurve curve, String header, String kasURL);
    }

    // TODO: add KAS
    public interface Services extends AutoCloseable {
        AuthorizationServiceFutureStub authorization();
        AttributesServiceFutureStub attributes();
        NamespaceServiceFutureStub namespaces();
        SubjectMappingServiceFutureStub subjectMappings();
        ResourceMappingServiceFutureStub resourceMappings();
        KAS kas();

        static Services newServices(ManagedChannel channel, KAS kas) {
            var attributeService = AttributesServiceGrpc.newFutureStub(channel);
            var namespaceService = NamespaceServiceGrpc.newFutureStub(channel);
            var subjectMappingService = SubjectMappingServiceGrpc.newFutureStub(channel);
            var resourceMappingService = ResourceMappingServiceGrpc.newFutureStub(channel);
            var authorizationService = AuthorizationServiceGrpc.newFutureStub(channel);

            return new Services() {
                @Override
                public void close() throws Exception {
                    channel.shutdownNow();
                    kas.close();
                }

                @Override
                public AttributesServiceFutureStub attributes() {
                    return attributeService;
                }

                @Override
                public NamespaceServiceFutureStub namespaces() {
                    return namespaceService;
                }

                @Override
                public SubjectMappingServiceFutureStub subjectMappings() {
                    return subjectMappingService;
                }

                @Override
                public ResourceMappingServiceFutureStub resourceMappings() {
                    return resourceMappingService;
                }

                @Override
                public AuthorizationServiceFutureStub authorization() {
                    return authorizationService;
                }

                @Override
                public KAS kas() {
                    return kas;
                }
            };
        }
    }

    SDK(Services services) {
        this.services = services;
    }

    public Services getServices(){
        return this.services;
    }
}