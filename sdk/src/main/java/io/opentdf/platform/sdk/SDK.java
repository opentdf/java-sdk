package io.opentdf.platform.sdk;

import com.nimbusds.jose.JOSEException;
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
import io.opentdf.platform.policy.kasregistry.KeyAccessServerRegistryServiceGrpc;
import io.opentdf.platform.policy.kasregistry.KeyAccessServerRegistryServiceGrpc.KeyAccessServerRegistryServiceFutureStub;
import io.opentdf.platform.sdk.nanotdf.NanoTDFType;
import org.apache.commons.codec.DecoderException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Optional;
import java.util.concurrent.ExecutionException;

/**
 * The SDK class represents a software development kit for interacting with the
 * opentdf platform. It
 * provides various services and stubs for making API calls to the opentdf
 * platform.
 */
public class SDK implements AutoCloseable {
    private final Services services;
    private final TrustManager trustManager;
    private final ClientInterceptor authInterceptor;
    private final String platformUrl;

    private static final Logger log = LoggerFactory.getLogger(SDK.class);

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
        AuthorizationServiceFutureStub authorization();

        AttributesServiceFutureStub attributes();

        NamespaceServiceFutureStub namespaces();

        SubjectMappingServiceFutureStub subjectMappings();

        ResourceMappingServiceFutureStub resourceMappings();

        KeyAccessServerRegistryServiceFutureStub kasRegistry();

        KAS kas();

        static Services newServices(ManagedChannel channel, KAS kas) {
            var attributeService = AttributesServiceGrpc.newFutureStub(channel);
            var namespaceService = NamespaceServiceGrpc.newFutureStub(channel);
            var subjectMappingService = SubjectMappingServiceGrpc.newFutureStub(channel);
            var resourceMappingService = ResourceMappingServiceGrpc.newFutureStub(channel);
            var authorizationService = AuthorizationServiceGrpc.newFutureStub(channel);
            var kasRegistryService = KeyAccessServerRegistryServiceGrpc.newFutureStub(channel);

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
                public KeyAccessServerRegistryServiceFutureStub kasRegistry() {
                    return kasRegistryService;
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

    SDK(Services services, TrustManager trustManager, ClientInterceptor authInterceptor, String platformUrl) {
        this.platformUrl = platformUrl;
        this.services = services;
        this.trustManager = trustManager;
        this.authInterceptor = authInterceptor;
    }

    public Services getServices() {
        return this.services;
    }

    public TDF.Reader loadTDF(SeekableByteChannel channel, Config.TDFReaderConfig config) throws SDKException, IOException {
        var tdf = new TDF(services);
        return tdf.loadTDF(channel, config, platformUrl);
    }

    public TDF.TDFObject createTDF(InputStream payload, OutputStream outputStream, Config.TDFConfig config) throws SDKException, IOException {
        var tdf = new TDF(services);
        return tdf.createTDF(payload, outputStream, config);
    }

    public int createNanoTDF(ByteBuffer payload, OutputStream outputStream, Config.NanoTDFConfig config) throws SDKException, IOException {
        var ntdf = new NanoTDF(services);
        return ntdf.createNanoTDF(payload, outputStream, config);
    }

    public void readNanoTDF(ByteBuffer nanoTDF, OutputStream out, Config.NanoTDFReaderConfig config) throws SDKException, IOException {
        var ntdf = new NanoTDF(services);
        ntdf.readNanoTDF(nanoTDF, out, config, platformUrl);
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

    public String getPlatformUrl() {
        return platformUrl;
    }
}
