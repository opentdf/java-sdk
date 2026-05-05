package io.opentdf.platform.sdk;

import com.connectrpc.Interceptor;
import com.connectrpc.ResponseMessageKt;
import com.connectrpc.impl.ProtocolClient;
import io.opentdf.platform.authorization.AuthorizationServiceClientInterface;
import io.opentdf.platform.authorization.Entity;
import io.opentdf.platform.authorization.EntityEntitlements;
import io.opentdf.platform.authorization.GetEntitlementsRequest;
import io.opentdf.platform.authorization.GetEntitlementsResponse;
import io.opentdf.platform.policy.Attribute;
import io.opentdf.platform.policy.PageRequest;
import io.opentdf.platform.policy.SimpleKasKey;
import io.opentdf.platform.policy.Value;
import io.opentdf.platform.policy.attributes.AttributesServiceClientInterface;
import io.opentdf.platform.policy.attributes.GetAttributeRequest;
import io.opentdf.platform.policy.attributes.GetAttributeValuesByFqnsRequest;
import io.opentdf.platform.policy.attributes.GetAttributeValuesByFqnsResponse;
import io.opentdf.platform.policy.attributes.ListAttributesRequest;
import io.opentdf.platform.policy.kasregistry.KeyAccessServerRegistryServiceClientInterface;
import io.opentdf.platform.policy.namespaces.NamespaceServiceClientInterface;
import io.opentdf.platform.policy.resourcemapping.ResourceMappingServiceClientInterface;
import io.opentdf.platform.policy.subjectmapping.SubjectMappingServiceClientInterface;
import io.opentdf.platform.wellknownconfiguration.WellKnownServiceClientInterface;

import javax.net.ssl.TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.SeekableByteChannel;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * The SDK class represents a software development kit for interacting with the
 * opentdf platform. It
 * provides various services and stubs for making API calls to the opentdf
 * platform.
 */
public class SDK implements AutoCloseable {

    // Caps the pagination loop in listAttributes to prevent unbounded memory growth
    // if a server repeatedly returns a non-zero next_offset.
    private static final int MAX_LIST_ATTRIBUTES_PAGES = 1000;

    // Matches the server-side limit on GetAttributeValuesByFqns so callers get a
    // clear local error instead of a cryptic server rejection.
    private static final int MAX_VALIDATE_FQNS = 250;

    private final Services services;
    private final TrustManager trustManager;
    private final Interceptor authInterceptor;
    private final String platformUrl;
    private final ProtocolClient platformServicesClient;
    private final SrtSigner srtSigner;

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

        byte[] unwrap(Manifest.KeyAccess keyAccess, String policy,
                      KeyType sessionKeyType);

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

        io.opentdf.platform.authorization.v2.AuthorizationServiceClientInterface authorizationV2();

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

    SDK(Services services, TrustManager trustManager, Interceptor authInterceptor, ProtocolClient platformServicesClient, String platformUrl, SrtSigner srtSigner) {
        this.platformUrl = platformUrl;
        this.services = services;
        this.trustManager = trustManager;
        this.authInterceptor = authInterceptor;
        this.platformServicesClient = platformServicesClient;
        this.srtSigner = srtSigner;
    }

    public Services getServices() {
        return this.services;
    }

    /**
     * Fetch the platform "base key" from the well-known configuration, if present.
     * <p>
     * This is read from the {@code base_key} field returned by {@code GetWellKnownConfiguration}.
     */
    public Optional<SimpleKasKey> getBaseKey() {
        return Planner.fetchBaseKey(services.wellknown());
    }

    public TDF.Reader loadTDF(SeekableByteChannel channel, Config.TDFReaderConfig config) throws SDKException, IOException {
        var tdf = new TDF(services);
        return tdf.loadTDF(channel, config, platformUrl);
    }

    public Manifest createTDF(InputStream payload, OutputStream outputStream, Config.TDFConfig config) throws SDKException, IOException {
        var tdf = new TDF(services);
        return tdf.createTDF(payload, outputStream, config).getManifest();
    }

    public ProtocolClient getPlatformServicesClient() {
        return this.platformServicesClient;
    }

    public Optional<SrtSigner> getSrtSigner() {
        return Optional.ofNullable(srtSigner);
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
     * Lists all active attributes available on the platform, auto-paginating through all results.
     * An optional namespace name or ID may be provided to filter results.
     *
     * <p>Use this before calling {@code createTDF()} to see what attributes are available for data tagging.
     *
     * @param namespace optional namespace name or ID to filter results
     * @return list of all active {@link Attribute} objects
     * @throws SDKException if a service error occurs or pagination exceeds the maximum page limit
     */
    public List<Attribute> listAttributes(String... namespace) {
        ListAttributesRequest.Builder reqBuilder = ListAttributesRequest.newBuilder();
        if (namespace.length > 0 && namespace[0] != null) {
            reqBuilder.setNamespace(namespace[0]);
        }
        List<Attribute> result = new ArrayList<>();
        for (int pages = 0; pages < MAX_LIST_ATTRIBUTES_PAGES; pages++) {
            var resp = ResponseMessageKt.getOrThrow(
                    services.attributes()
                            .listAttributesBlocking(reqBuilder.build(), Collections.emptyMap())
                            .execute());
            result.addAll(resp.getAttributesList());
            int nextOffset = resp.getPagination().getNextOffset();
            if (nextOffset == 0) {
                return result;
            }
            reqBuilder.setPagination(PageRequest.newBuilder().setOffset(nextOffset).build());
        }
        throw new SDKException("listing attributes: exceeded maximum page limit (" + MAX_LIST_ATTRIBUTES_PAGES + ")");
    }

    /**
     * Checks that all provided attribute value FQNs exist on the platform.
     * Validates FQN format first, then verifies existence via the platform API.
     *
     * <p>Use this before {@code createTDF()} to catch missing or misspelled attributes early
     * instead of discovering the problem at decryption time.
     *
     * @param fqns list of attribute value FQNs in the form
     *             {@code https://<namespace>/attr/<name>/value/<value>}
     * @throws AttributeNotFoundException if any FQNs are not found on the platform
     * @throws SDKException if input validation fails or a service error occurs
     */
    public void validateAttributes(List<String> fqns) {
        if (fqns == null || fqns.isEmpty()) {
            return;
        }
        if (fqns.size() > MAX_VALIDATE_FQNS) {
            throw new SDKException("too many attribute FQNs: " + fqns.size()
                    + " exceeds maximum of " + MAX_VALIDATE_FQNS);
        }
        for (String fqn : fqns) {
            try {
                new Autoconfigure.AttributeValueFQN(fqn);
            } catch (AutoConfigureException e) {
                throw new SDKException("invalid attribute value FQN \"" + fqn + "\": " + e.getMessage(), e);
            }
        }
        GetAttributeValuesByFqnsResponse resp = ResponseMessageKt.getOrThrow(
                services.attributes()
                        .getAttributeValuesByFqnsBlocking(
                                GetAttributeValuesByFqnsRequest.newBuilder().addAllFqns(fqns).build(),
                                Collections.emptyMap())
                        .execute());
        Map<String, GetAttributeValuesByFqnsResponse.AttributeAndValue> found = resp.getFqnAttributeValuesMap();
        List<String> missing = fqns.stream()
                .filter(f -> !found.containsKey(f))
                .collect(Collectors.toList());
        if (!missing.isEmpty()) {
            throw new AttributeNotFoundException("attribute not found: " + String.join(", ", missing));
        }
    }

    /**
     * Returns the attribute value FQNs assigned to an entity (person or non-person entity).
     *
     * <p>Use this to inspect what attributes a user, service account, or other entity has been
     * granted before making authorization decisions or constructing access policies.
     *
     * @param entity the entity to look up; must not be null
     * @return list of attribute value FQNs assigned to the entity, or an empty list if none
     * @throws SDKException if entity is null or a service error occurs
     */
    public List<String> getEntityAttributes(Entity entity) {
        if (entity == null) {
            throw new SDKException("entity must not be null");
        }
        GetEntitlementsResponse resp = ResponseMessageKt.getOrThrow(
                services.authorization()
                        .getEntitlementsBlocking(
                                GetEntitlementsRequest.newBuilder().addEntities(entity).build(),
                                Collections.emptyMap())
                        .execute());
        String entityId = entity.getId();
        for (EntityEntitlements e : resp.getEntitlementsList()) {
            if (e.getEntityId().equals(entityId)) {
                return e.getAttributeValueFqnsList();
            }
        }
        return Collections.emptyList();
    }

    /**
     * Reports whether the attribute definition identified by {@code attributeFqn} exists on the
     * platform.
     *
     * <p>{@code attributeFqn} should be an attribute-level FQN (no {@code /value/} segment):
     * <pre>{@code https://<namespace>/attr/<attribute_name>}</pre>
     *
     * @param attributeFqn the attribute-level FQN to check
     * @return {@code true} if the attribute exists, {@code false} if it does not
     * @throws SDKException if the FQN format is invalid or a non-not-found service error occurs
     */
    public boolean attributeExists(String attributeFqn) {
        try {
            new Autoconfigure.AttributeNameFQN(attributeFqn);
        } catch (AutoConfigureException e) {
            throw new SDKException("invalid attribute FQN \"" + attributeFqn + "\": " + e.getMessage(), e);
        }
        try {
            ResponseMessageKt.getOrThrow(
                    services.attributes()
                            .getAttributeBlocking(
                                    GetAttributeRequest.newBuilder().setFqn(attributeFqn).build(),
                                    Collections.emptyMap())
                            .execute());
            return true;
        } catch (Exception e) {
            String msg = e.getMessage();
            if (msg != null && msg.contains("not_found")) {
                return false;
            }
            throw new SDKException("checking attribute existence: " + msg, e);
        }
    }

    /**
     * Reports whether the attribute value FQN exists on the platform.
     *
     * <p>{@code valueFqn} should be a full attribute value FQN (with {@code /value/} segment):
     * <pre>{@code https://<namespace>/attr/<attribute_name>/value/<value>}</pre>
     *
     * @param valueFqn the attribute value FQN to check
     * @return {@code true} if the value exists, {@code false} if it does not
     * @throws SDKException if the FQN format is invalid or a service error occurs
     */
    public boolean attributeValueExists(String valueFqn) {
        try {
            new Autoconfigure.AttributeValueFQN(valueFqn);
        } catch (AutoConfigureException e) {
            throw new SDKException("invalid attribute value FQN \"" + valueFqn + "\": " + e.getMessage(), e);
        }
        GetAttributeValuesByFqnsResponse resp;
        try {
            resp = ResponseMessageKt.getOrThrow(
                    services.attributes()
                            .getAttributeValuesByFqnsBlocking(
                                    GetAttributeValuesByFqnsRequest.newBuilder().addFqns(valueFqn).build(),
                                    Collections.emptyMap())
                            .execute());
        } catch (Exception e) {
            throw new SDKException("checking attribute value existence: " + e.getMessage(), e);
        }
        return resp.getFqnAttributeValuesMap().containsKey(valueFqn);
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

    /**
     * {@link AttributeNotFoundException} is thrown by {@link #validateAttributes(List)},
     * {@link #validateAttributeExists(String)}, and
     * {@link #validateAttributeValue(String, String)} when one or more attributes or values
     * are not found on the platform.
     */
    public static class AttributeNotFoundException extends SDKException {
        public AttributeNotFoundException(String errorMessage) {
            super(errorMessage);
        }
    }
}
