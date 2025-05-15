package io.opentdf.platform.sdk;

import com.connectrpc.Interceptor;
import com.connectrpc.impl.ProtocolClient;
import io.opentdf.platform.authorization.AuthorizationServiceClient;
import io.opentdf.platform.policy.attributes.AttributesServiceClient;
import io.opentdf.platform.policy.kasregistry.KeyAccessServerRegistryServiceClient;
import io.opentdf.platform.policy.namespaces.NamespaceServiceClient;
import io.opentdf.platform.policy.resourcemapping.ResourceMappingServiceClient;
import io.opentdf.platform.policy.subjectmapping.SubjectMappingServiceClient;
import io.opentdf.platform.sdk.nanotdf.NanoTDFType;

import javax.net.ssl.TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
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
    private final ProtocolClient protocolClient;
    private final String platformUrl;

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

        KeyAccessServerRegistryServiceClient kasRegistry();

        KAS kas();
    }

    public Optional<TrustManager> getTrustManager() {
        return Optional.ofNullable(trustManager);
    }

    public Optional<Interceptor> getAuthInterceptor() {
        return Optional.ofNullable(authInterceptor);
    }

    public ProtocolClient getProtocolClient() {
        return protocolClient;
    }

    SDK(Services services, TrustManager trustManager, Interceptor authInterceptor, ProtocolClient protocolClient, String platformUrl) {
        this.protocolClient = protocolClient;
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
