package io.opentdf.platform.sdk;

import com.connectrpc.Interceptor;

import com.connectrpc.impl.ProtocolClient;
import io.opentdf.platform.authorization.AuthorizationServiceClientInterface;
import io.opentdf.platform.policy.attributes.AttributesServiceClientInterface;
import io.opentdf.platform.policy.kasregistry.KeyAccessServerRegistryServiceClientInterface;
import io.opentdf.platform.policy.namespaces.NamespaceServiceClientInterface;
import io.opentdf.platform.policy.resourcemapping.ResourceMappingServiceClientInterface;
import io.opentdf.platform.policy.subjectmapping.SubjectMappingServiceClientInterface;
import io.opentdf.platform.wellknownconfiguration.WellKnownServiceClientInterface;

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
    private final String platformUrl;
    private final ProtocolClient platformServicesClient;

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
        AttributesServiceClientInterface attributes();

        NamespaceServiceClientInterface namespaces();

        SubjectMappingServiceClientInterface subjectMappings();

        ResourceMappingServiceClientInterface resourceMappings();

        AuthorizationServiceClientInterface authorization();

        KeyAccessServerRegistryServiceClientInterface kasRegistry();

        WellKnownServiceClientInterface wellknown();

        KAS kas();
    }

    public Optional<TrustManager> getTrustManager() {
        return Optional.ofNullable(trustManager);
    }

    public Optional<Interceptor> getAuthInterceptor() {
        return Optional.ofNullable(authInterceptor);
    }

    SDK(Services services, TrustManager trustManager, Interceptor authInterceptor, ProtocolClient platformServicesClient, String platformUrl) {
        this.platformUrl = platformUrl;
        this.services = services;
        this.trustManager = trustManager;
        this.authInterceptor = authInterceptor;
        this.platformServicesClient = platformServicesClient;
    }

    public Services getServices() {
        return this.services;
    }

    public TDF.Reader loadTDF(SeekableByteChannel channel, Config.TDFReaderConfig config) throws SDKException, IOException {
        var tdf = new TDF(services);
        return tdf.loadTDF(channel, config, platformUrl);
    }

    public Manifest createTDF(InputStream payload, OutputStream outputStream, Config.TDFConfig config) throws SDKException, IOException {
        var tdf = new TDF(services);
        return tdf.createTDF(payload, outputStream, config).getManifest();
    }

    public int createNanoTDF(ByteBuffer payload, OutputStream outputStream, Config.NanoTDFConfig config) throws SDKException, IOException {
        var ntdf = new NanoTDF(services);
        return ntdf.createNanoTDF(payload, outputStream, config);
    }

    public void readNanoTDF(ByteBuffer nanoTDF, OutputStream out, Config.NanoTDFReaderConfig config) throws SDKException, IOException {
        var ntdf = new NanoTDF(services);
        ntdf.readNanoTDF(nanoTDF, out, config, platformUrl);
    }

    public ProtocolClient getPlatformServicesClient() {
        return this.platformServicesClient;
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

    /**
     * Reads the {@link Manifest} without decrypting the TDF
     * @param tdfBytes A SeekableByteChannel containing the TDF data
     * @return The parsed {@link Manifest} object
     * @throws SDKException if an SDK-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    public static Manifest readManifest(SeekableByteChannel tdfBytes) throws SDKException, IOException {
        TDFReader reader = new TDFReader(tdfBytes);
        String manifestJson = reader.manifest();
        return Manifest.readManifest(manifestJson);
    }

    /**
     * Decodes a PolicyObject from the manifest. Use {@link SDK#readManifest(SeekableByteChannel)}
     * to get the {@link Manifest} from a TDF.
     * @param manifest The {@link Manifest} containing the policy.
     * @return The decoded {@link PolicyObject}.
     * @throws {@link SDKException} if there is an error during decoding.
     */
    public static PolicyObject decodePolicyObject(Manifest manifest) throws SDKException {
        return Manifest.decodePolicyObject(manifest);
    }

    public String getPlatformUrl() {
        return platformUrl;
    }

    /**
     *  Indicates that the TDF is malformed in some way
     */
    public static class MalformedTDFException extends SDKException {
        public MalformedTDFException(String errorMessage) {
            super(errorMessage);
        }
    }

    /**
     * {@link SplitKeyException} is thrown when the SDK encounters an error related to
     * the inability to reconstruct a split key during decryption.
     */
    public static class SplitKeyException extends SDKException {
        public SplitKeyException(String errorMessage) {
            super(errorMessage);
        }
    }

    /**
     * {@link DataSizeNotSupported} is thrown when the user attempts to create
     * a TDF with a size larger than the maximum size (currently 64GiB).
     */
    public static class DataSizeNotSupported extends SDKException {
        public DataSizeNotSupported(String errorMessage) {
            super(errorMessage);
        }
    }

    /**
     * {@link KasInfoMissing} is thrown during TDF creation when no KAS information is present.
     */
    public static class KasInfoMissing extends SDKException {
        public KasInfoMissing(String errorMessage) {
            super(errorMessage);
        }
    }

    /**
     * {@link KasPublicKeyMissing} is thrown during encryption
     *  when the SDK cannot retrieve the public key for a KAS.
     */
    public static class KasPublicKeyMissing extends SDKException {
        public KasPublicKeyMissing(String errorMessage) {
            super(errorMessage);
        }
    }

    /**
     * {@link TamperException} is the base class for exceptions related to signature mismatches.
     */
    public static class TamperException extends SDKException {
        public TamperException(String errorMessage) {
            super("[tamper detected] "+errorMessage);
        }
    }

    /**
     * {@link RootSignatureValidationException} is thrown when the signature on the overall
     * TDF fails.
     */
    public static class RootSignatureValidationException extends TamperException {
        public RootSignatureValidationException(String errorMessage) {
            super(errorMessage);
        }
    }

    /**
     * {@link SegmentSignatureMismatch} is thrown when the segment signature does not
     * match the expected signature.
     */
    public static class SegmentSignatureMismatch extends TamperException {
        public SegmentSignatureMismatch(String errorMessage) {
            super(errorMessage);
        }
    }

    /**
     * {@link KasBadRequestException} is thrown when a KAS returns a 400 error.
     */
    public static class KasBadRequestException extends TamperException {
        public KasBadRequestException(String errorMessage) {
            super(errorMessage);
        }
    }

   /**
     * {@link KasAllowlistException} is thrown during decryption when a TDF refers to
    * a KAS that is not in the allowlist.
     */
    public static class KasAllowlistException extends SDKException {
        public KasAllowlistException(String errorMessage) {
            super(errorMessage);
        }
    }

    /**
     * {@link AssertionException} indicates that an assertion was not validated due to
     * an incorrect signature.
     */
    public static class AssertionException extends TamperException {
        public AssertionException(String errorMessage, String id) {
            super("assertion id: "+ id + "; " + errorMessage);
        }
    }
}
