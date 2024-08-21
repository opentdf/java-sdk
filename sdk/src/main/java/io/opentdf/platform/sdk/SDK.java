package io.opentdf.platform.sdk;

import io.grpc.ClientInterceptor;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.TrustManager;
import java.io.IOException;
import java.nio.channels.SeekableByteChannel;
import java.util.Optional;

/**
 * The SDK class represents a software development kit for interacting with the opentdf platform. It
 * provides various services and stubs for making API calls to the opentdf platform.
 */
public class SDK implements AutoCloseable {
    private final Services services;
    private final TrustManager trustManager;
    private final ClientInterceptor authInterceptor;

    private static final Logger log = LoggerFactory.getLogger(SDK.class);

    @Override
    public void close() throws Exception {
        services.close();
    }

    public interface KAS extends AutoCloseable {
        Config.KASInfo getPublicKey(Config.KASInfo kasInfo);
        String getECPublicKey(Config.KASInfo kasInfo, NanoTDFType.ECCurve curve);
        byte[] unwrap(Manifest.KeyAccess keyAccess, String policy);
        byte[] unwrapNanoTDF(NanoTDFType.ECCurve curve, String header, String kasURL);
        KASKeyCache getKeyCache();
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

    public Optional<TrustManager> getTrustManager() {
        return Optional.ofNullable(trustManager);
    }

    public Optional<ClientInterceptor> getAuthInterceptor() {
        return Optional.ofNullable(authInterceptor);
    }

    SDK(Services services, TrustManager trustManager, ClientInterceptor authInterceptor) {
        this.services = services;
        this.trustManager = trustManager;
        this.authInterceptor = authInterceptor;
    }

    public Services getServices() {
        return this.services;
    }

    /**
     * Checks to see if this has the structure of a Z-TDF in that it is a zip file containing
     * a `manifest.json` and a `0.payload`
     * @param channel A channel containing the bytes of the potential Z-TDF
     * @return `true` if
     */
    public static boolean isTDF(SeekableByteChannel channel) {
        ZipReader zipReader;
        try {
            zipReader = new ZipReader(channel);
        } catch (IOException | InvalidZipException e) {
            return false;
        }
        var entries = zipReader.getEntries();
        if (entries.size() != 2) {
            return false;
        }
        return entries.stream().anyMatch(e -> "0.manifest.json".equals(e.getName()))
                && entries.stream().anyMatch(e -> "0.payload".equals(e.getName()));
    }
}
