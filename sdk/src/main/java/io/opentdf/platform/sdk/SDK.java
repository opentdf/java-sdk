package io.opentdf.platform.sdk;

import com.connectrpc.Interceptor;
import com.connectrpc.impl.ProtocolClient;
import io.opentdf.platform.generated.authorization.AuthorizationServiceClient;
import io.opentdf.platform.generated.policy.attributes.AttributesServiceClient;
import io.opentdf.platform.generated.policy.namespaces.NamespaceServiceClient;
import io.opentdf.platform.generated.policy.resourcemapping.ResourceMappingServiceClient;
import io.opentdf.platform.generated.policy.subjectmapping.SubjectMappingServiceClient;
import io.opentdf.platform.sdk.nanotdf.NanoTDFType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.TrustManager;
import java.io.IOException;
import java.nio.channels.SeekableByteChannel;
import java.util.Optional;

/**
 * The SDK class represents a software development kit for interacting with the
 * opentdf platform. It
 * provides various services and stubs for making API calls to the opentdf
 * platform.
 */
public class SDK implements AutoCloseable {
    private final Services services;
    private final TrustManager trustManager;
    private final Interceptor authInterceptor;

    /**
     * Closes the SDK, including its associated services.
     *
     * @throws Exception if an error occurs while closing the services.
     */
    @Override
    public void close() throws Exception {
        services.close();
    }

    /**
     * KAS (Key Access Service) interface to define methods related to key access and management.
     * This interface extends AutoCloseable to allow for resource management during close operations.
     */
    public interface KAS extends AutoCloseable {
        Config.KASInfo getPublicKey(Config.KASInfo kasInfo);

        Config.KASInfo getECPublicKey(Config.KASInfo kasInfo, NanoTDFType.ECCurve curve);

        byte[] unwrap(Manifest.KeyAccess keyAccess, String policy,
                      KeyType sessionKeyType);

        byte[] unwrapNanoTDF(NanoTDFType.ECCurve curve, String header, String kasURL);

        KASKeyCache getKeyCache();
    }

    /**
     * The Services interface provides access to various gRPC service stubs and a Key Authority Service (KAS).
     * It extends the AutoCloseable interface, allowing for the release of resources when no longer needed.
     */
    public interface Services extends AutoCloseable {
        AttributesServiceClient attributes();

        NamespaceServiceClient namespaces();

        SubjectMappingServiceClient subjectMappings();

        ResourceMappingServiceClient resourceMappings();

        AuthorizationServiceClient authorization();

        KAS kas();

        static Services newServices(ProtocolClient client, KAS kas) {
            var attributeService = new AttributesServiceClient(client);
            var namespaceService = new NamespaceServiceClient(client);
            var subjectMappingService = new SubjectMappingServiceClient(client);
            var resourceMappingService = new ResourceMappingServiceClient(client);
            var authorizationService = new AuthorizationServiceClient(client);

            return new Services() {
                @Override
                public void close() throws Exception {
                    kas.close();
                }

                @Override
                public AttributesServiceClient attributes() {
                    return attributeService;
                }

                @Override
                public NamespaceServiceClient namespaces() {
                    return namespaceService;
                }

                @Override
                public SubjectMappingServiceClient subjectMappings() {
                    return subjectMappingService;
                }

                @Override
                public ResourceMappingServiceClient resourceMappings() {
                    return resourceMappingService;
                }

                @Override
                public AuthorizationServiceClient authorization() {
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

    public Optional<Interceptor> getAuthInterceptor() {
        return Optional.ofNullable(authInterceptor);
    }

    SDK(Services services, TrustManager trustManager, Interceptor authInterceptor) {
        this.services = services;
        this.trustManager = trustManager;
        this.authInterceptor = authInterceptor;
    }

    public Services getServices() {
        return this.services;
    }

    /**
     * Checks to see if this has the structure of a Z-TDF in that it is a zip file
     * containing
     * a `manifest.json` and a `0.payload`
     * 
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
