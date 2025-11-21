package io.opentdf.platform.sdk;

import com.connectrpc.ResponseMessageKt;
import io.opentdf.platform.policy.kasregistry.ListKeyAccessServersRequest;
import io.opentdf.platform.policy.kasregistry.ListKeyAccessServersResponse;
import io.opentdf.platform.sdk.SDK.KasAllowlistException;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import io.opentdf.platform.wellknownconfiguration.WellKnownServiceClientInterface;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The NanoTDF class provides methods to create and read NanoTDF (Tiny Data Format) files.
 * The NanoTDF format is intended for securely encrypting small data payloads using elliptic-curve cryptography
 * and authenticated encryption.
 */
class NanoTDF {

    public static Logger logger = LoggerFactory.getLogger(NanoTDF.class);

    public static final byte[] MAGIC_NUMBER_AND_VERSION = new byte[] { 0x4C, 0x31, 0x4C };
    private static final int kMaxTDFSize = ((16 * 1024 * 1024) - 3 - 32); // 16 mb - 3(iv) - 32(max auth tag)
    private static final int kNanoTDFGMACLength = 8;
    private static final int kIvPadding = 9;
    private static final int kNanoTDFIvSize = 3;
    private static final byte[] kEmptyIV = new byte[] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
    private final SDK.Services services;
    private final CollectionStore collectionStore;

    NanoTDF(SDK.Services services) {
        this(services, new CollectionStore.NoOpCollectionStore());
    }

    NanoTDF(SDK.Services services, CollectionStore collectionStore) {
        this.services = services;
        this.collectionStore = collectionStore;
    }

    public static class NanoTDFMaxSizeLimit extends SDKException {
        public NanoTDFMaxSizeLimit(String errorMessage) {
            super(errorMessage);
        }
    }

    public static class UnsupportedNanoTDFFeature extends SDKException {
        public UnsupportedNanoTDFFeature(String errorMessage) {
            super(errorMessage);
        }
    }

    public static class InvalidNanoTDFConfig extends SDKException {
        public InvalidNanoTDFConfig(String errorMessage) {
            super(errorMessage);
        }
    }

    private static Optional<Config.KASInfo> getBaseKey(WellKnownServiceClientInterface wellKnownService) {
        return Planner.fetchBaseKey(wellKnownService).map(k -> {
            if (!KeyType.fromAlgorithm(k.getPublicKey().getAlgorithm()).isEc()) {
                throw new SDKException(String.format("base key is not an EC key, cannot create NanoTDF using a key of type %s",
                        k.getPublicKey().getAlgorithm()));
            }
            return Config.KASInfo.fromSimpleKasKey(k);
        });
    }

    private Optional<Config.KASInfo> getKasInfo(Config.NanoTDFConfig nanoTDFConfig) {
        if (nanoTDFConfig.getKasInfoList().isEmpty()) {
            logger.debug("no kas info provided in NanoTDFConfig");
            return Optional.empty();
        }
        return Optional.of(nanoTDFConfig.getKasInfoList().get(0));
    }

    private Config.HeaderInfo getHeaderInfo(Config.NanoTDFConfig nanoTDFConfig) throws InvalidNanoTDFConfig, UnsupportedNanoTDFFeature {
        if (nanoTDFConfig.getCollectionConfig().getUseCollection()) {
            Config.HeaderInfo headerInfo = nanoTDFConfig.getCollectionConfig().getHeaderInfo();
            if (headerInfo != null) {
                return headerInfo;
            }
        }

        Gson gson = new GsonBuilder().create();
        Config.KASInfo kasInfo = getKasInfo(nanoTDFConfig)
                .or(() -> NanoTDF.getBaseKey(services.wellknown()))
                .orElseThrow(() -> new SDKException("no KAS info provided and couldn't get base key, cannot create NanoTDF"));

        String url = kasInfo.getURL();
        if (kasInfo.getPublicKey() == null || kasInfo.getPublicKey().isEmpty()) {
            logger.info("no public key provided for KAS at {}, retrieving", url);
            kasInfo = services.kas().getECPublicKey(kasInfo, nanoTDFConfig.getEccMode().getCurve());
        }

        // Kas url resource locator
        ResourceLocator kasURL = new ResourceLocator(kasInfo.getURL(), kasInfo.getKID());
        assert kasURL.getIdentifier() != null : "Identifier in ResourceLocator cannot be null";

        NanoTDFType.ECCurve ecCurve = getEcCurve(nanoTDFConfig, kasInfo);
        ECKeyPair keyPair = new ECKeyPair(ecCurve, ECKeyPair.ECAlgorithm.ECDSA);

        // Generate symmetric key
        ECPublicKey kasPublicKey = ECKeyPair.publicKeyFromPem(kasInfo.getPublicKey());
        byte[] symmetricKey = ECKeyPair.computeECDHKey(kasPublicKey, keyPair.getPrivateKey());

        // Generate HKDF key
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new SDKException("error getting instance of SHA-256 digest", e);
        }
        byte[] hashOfSalt = digest.digest(MAGIC_NUMBER_AND_VERSION);
        byte[] key = ECKeyPair.calculateHKDF(hashOfSalt, symmetricKey);

        // Encrypt policy
        PolicyObject policyObject = createPolicyObject(nanoTDFConfig.getAttributes());
        String policyObjectAsStr = gson.toJson(policyObject);

        logger.debug("createNanoTDF policy object - {}", policyObjectAsStr);

        // Set policy body and embed in header, either as plain text or encrypted
        final byte[] policyBody;
        PolicyInfo policyInfo = new PolicyInfo();
        AesGcm gcm = new AesGcm(key);
        if (nanoTDFConfig.getPolicyType() == NanoTDFType.PolicyType.EMBEDDED_POLICY_PLAIN_TEXT) {
            policyBody = policyObjectAsStr.getBytes(StandardCharsets.UTF_8);
            policyInfo.setEmbeddedPlainTextPolicy(policyBody);
        } else {
            byte[] policyObjectAsBytes = policyObjectAsStr.getBytes(StandardCharsets.UTF_8);
            int authTagSize = SymmetricAndPayloadConfig.sizeOfAuthTagForCipher(nanoTDFConfig.getConfig().getCipherType());
            byte[] encryptedPolicy = gcm.encrypt(kEmptyIV, authTagSize, policyObjectAsBytes, 0, policyObjectAsBytes.length);
            policyBody = Arrays.copyOfRange(encryptedPolicy, kEmptyIV.length, encryptedPolicy.length);
            policyInfo.setEmbeddedEncryptedTextPolicy(policyBody);
        }

        // Set policy binding (GMAC)
        if (nanoTDFConfig.getEccMode().isECDSABindingEnabled()) {
            throw new UnsupportedNanoTDFFeature("ECDSA policy binding is not support");
        } else {
            byte[] hash = digest.digest(policyBody);
            byte[] gmac = Arrays.copyOfRange(hash, hash.length - kNanoTDFGMACLength, hash.length);
            policyInfo.setPolicyBinding(gmac);
        }

        // Create header
        byte[] compressedPubKey = keyPair.compressECPublickey();
        Header header = new Header();
        ECCMode mode;
        if (nanoTDFConfig.getEccMode().getCurve() != keyPair.getCurve()) {
            mode = new ECCMode(nanoTDFConfig.getEccMode().getECCModeAsByte());
            mode.setEllipticCurve(keyPair.getCurve());
        } else {
            mode = nanoTDFConfig.getEccMode();
        }
        header.setECCMode(mode);
        header.setPayloadConfig(nanoTDFConfig.getConfig());
        header.setEphemeralKey(compressedPubKey);
        header.setKasLocator(kasURL);
        header.setPolicyInfo(policyInfo);

        Config.HeaderInfo headerInfo = new Config.HeaderInfo(header, gcm, 0);
        if (nanoTDFConfig.getCollectionConfig().getUseCollection()) {
            nanoTDFConfig.getCollectionConfig().updateHeaderInfo(headerInfo);
        }

        return headerInfo;
    }

    private static NanoTDFType.ECCurve getEcCurve(Config.NanoTDFConfig nanoTDFConfig, Config.KASInfo kasInfo) {
        // it might be better to pull the curve from the OIDC in the PEM but it looks like we
        // are just taking the Algorithm as correct
        Optional<NanoTDFType.ECCurve> specifiedCurve = NanoTDFType.ECCurve.fromAlgorithm(kasInfo.getAlgorithm());
        NanoTDFType.ECCurve ecCurve;
        if (specifiedCurve.isEmpty()) {
            logger.info("no curve specified in KASInfo, using the curve from config [{}]", nanoTDFConfig.getEccMode().getCurve());
            ecCurve = nanoTDFConfig.getEccMode().getCurve();
        } else {
            if (specifiedCurve.get() != nanoTDFConfig.getEccMode().getCurve()) {
                logger.warn("ECCurve in NanoTDFConfig [{}] does not match the curve in KASInfo, using KASInfo curve [{}]", nanoTDFConfig.getEccMode().getCurve(), specifiedCurve.get());
            }
            ecCurve = specifiedCurve.get();
        }
        return ecCurve;
    }

    public int createNanoTDF(ByteBuffer data, OutputStream outputStream,
            Config.NanoTDFConfig nanoTDFConfig) throws SDKException, IOException {
        int nanoTDFSize = 0;

        int dataSize = data.limit();
        if (dataSize > kMaxTDFSize) {
            throw new NanoTDFMaxSizeLimit("exceeds max size for nano tdf");
        }

        // check the policy type, support only embedded policy
        if (nanoTDFConfig.getPolicyType() != NanoTDFType.PolicyType.EMBEDDED_POLICY_PLAIN_TEXT &&
                nanoTDFConfig.getPolicyType() != NanoTDFType.PolicyType.EMBEDDED_POLICY_ENCRYPTED) {
            throw new UnsupportedNanoTDFFeature("unsupported policy type");
        }

        Config.HeaderInfo headerKeyPair = getHeaderInfo(nanoTDFConfig);
        Header header = headerKeyPair.getHeader();
        AesGcm gcm = headerKeyPair.getKey();
        int iteration = headerKeyPair.getIteration();

        int headerSize = header.getTotalSize();
        ByteBuffer bufForHeader = ByteBuffer.allocate(headerSize);
        header.writeIntoBuffer(bufForHeader);

        // Write header
        outputStream.write(bufForHeader.array());
        nanoTDFSize += headerSize;
        logger.debug("createNanoTDF header length {}", headerSize);

        int authTagSize = SymmetricAndPayloadConfig.sizeOfAuthTagForCipher(nanoTDFConfig.getConfig().getCipherType());
        // Encrypt the data
        byte[] actualIV = new byte[kIvPadding + kNanoTDFIvSize];
        if (nanoTDFConfig.getCollectionConfig().getUseCollection()) {
            ByteBuffer b = ByteBuffer.allocate(4);
            b.order(ByteOrder.LITTLE_ENDIAN);
            b.putInt(iteration);
            System.arraycopy(b.array(), 0, actualIV, kIvPadding, kNanoTDFIvSize);
        } else {
            do {
                byte[] iv = new byte[kNanoTDFIvSize];
                try {
                    SecureRandom.getInstanceStrong().nextBytes(iv);
                } catch (NoSuchAlgorithmException e) {
                    throw new SDKException("error getting instance of strong SecureRandom", e);
                }
                System.arraycopy(iv, 0, actualIV, kIvPadding, iv.length);
            } while (Arrays.equals(actualIV, kEmptyIV));    // if match, we need to retry to prevent key + iv reuse with the policy
        }

        byte[] cipherData = gcm.encrypt(actualIV, authTagSize, data.array(), data.arrayOffset(), dataSize);

        // Write the length of the payload as int24
        int cipherDataLengthWithoutPadding = cipherData.length - kIvPadding;
        byte[] bgIntAsBytes = ByteBuffer.allocate(4).putInt(cipherDataLengthWithoutPadding).array();
        outputStream.write(bgIntAsBytes, 1, 3);
        nanoTDFSize += 3;

        logger.debug("createNanoTDF payload length {}", cipherDataLengthWithoutPadding);

        // Write the payload
        outputStream.write(cipherData, kIvPadding, cipherDataLengthWithoutPadding);
        nanoTDFSize += cipherDataLengthWithoutPadding;

        return nanoTDFSize;
    }

    public void readNanoTDF(ByteBuffer nanoTDF, OutputStream outputStream) throws IOException {
             readNanoTDF(nanoTDF, outputStream, Config.newNanoTDFReaderConfig());
    }

    public void readNanoTDF(ByteBuffer nanoTDF, OutputStream outputStream, String platformUrl) throws IOException {
             readNanoTDF(nanoTDF, outputStream, Config.newNanoTDFReaderConfig(), platformUrl);
    }


    public void readNanoTDF(ByteBuffer nanoTDF, OutputStream outputStream,
                            Config.NanoTDFReaderConfig nanoTdfReaderConfig, String platformUrl) throws IOException {
        if (!nanoTdfReaderConfig.isIgnoreKasAllowlist() && (nanoTdfReaderConfig.getKasAllowlist() == null || nanoTdfReaderConfig.getKasAllowlist().isEmpty())) {
            ListKeyAccessServersRequest request = ListKeyAccessServersRequest.newBuilder()
                    .build();
            ListKeyAccessServersResponse response = ResponseMessageKt.getOrThrow(services.kasRegistry().listKeyAccessServersBlocking(request, Collections.emptyMap()).execute());
            nanoTdfReaderConfig.setKasAllowlist(new HashSet<>());
            var kases = response.getKeyAccessServersList();

            for (var entry : kases) {
                nanoTdfReaderConfig.getKasAllowlist().add(Config.getKasAddress(entry.getUri()));
            }

            nanoTdfReaderConfig.getKasAllowlist().add(Config.getKasAddress(platformUrl));
        }
        readNanoTDF(nanoTDF, outputStream, nanoTdfReaderConfig);
    }


    public void readNanoTDF(ByteBuffer nanoTDF, OutputStream outputStream,
            Config.NanoTDFReaderConfig nanoTdfReaderConfig) throws IOException {

        Header header = new Header(nanoTDF);
        CollectionKey cachedKey = collectionStore.getKey(header);
        byte[] key = cachedKey.getKey();

        // perform unwrap is not in collectionStore;
        if (key == null) {
            // create base64 encoded
            byte[] headerData = new byte[header.getTotalSize()];
            header.writeIntoBuffer(ByteBuffer.wrap(headerData));
            String base64HeaderData = Base64.getEncoder().encodeToString(headerData);

            logger.debug("readNanoTDF header length {}", headerData.length);

            String kasUrl = header.getKasLocator().getResourceUrl();

            var realAddress = Config.getKasAddress(kasUrl);
            if (nanoTdfReaderConfig.isIgnoreKasAllowlist()) {
                logger.warn("Ignoring KasAllowlist for url {}", realAddress);
            } else if (nanoTdfReaderConfig.getKasAllowlist() == null || nanoTdfReaderConfig.getKasAllowlist().isEmpty()) {
                logger.error("KasAllowlist: No KAS allowlist provided and no KeyAccessServerRegistry available, {} is not allowed", realAddress);
                throw new KasAllowlistException("No KAS allowlist provided and no KeyAccessServerRegistry available");
            } else if (!nanoTdfReaderConfig.getKasAllowlist().contains(realAddress)) {
                logger.error("KasAllowlist: kas url {} is not allowed", realAddress);
                throw new KasAllowlistException("KasAllowlist: kas url "+realAddress+" is not allowed");
            }


            key = services.kas().unwrapNanoTDF(header.getECCMode().getCurve(),
                    base64HeaderData,
                    kasUrl);
            collectionStore.store(header, new CollectionKey(key));
        }

        byte[] payloadLengthBuf = new byte[4];
        nanoTDF.get(payloadLengthBuf, 1, 3);
        int payloadLength = ByteBuffer.wrap(payloadLengthBuf).getInt();

        logger.debug("readNanoTDF payload length {}, retrieving", payloadLength);

        // Read iv
        byte[] iv = new byte[kNanoTDFIvSize];
        nanoTDF.get(iv);

        // pad the IV with zero's
        byte[] ivPadded = new byte[AesGcm.GCM_NONCE_LENGTH];
        System.arraycopy(iv, 0, ivPadded, kIvPadding, iv.length);

        byte[] cipherData = new byte[payloadLength - kNanoTDFIvSize];
        nanoTDF.get(cipherData);

        int authTagSize = SymmetricAndPayloadConfig.sizeOfAuthTagForCipher(header.getPayloadConfig().getCipherType());
        AesGcm gcm = new AesGcm(key);
        byte[] plainData = gcm.decrypt(ivPadded, authTagSize, cipherData);

        outputStream.write(plainData);
    }

    PolicyObject createPolicyObject(List<String> attributes) {
        PolicyObject policyObject = new PolicyObject();
        policyObject.body = new PolicyObject.Body();
        policyObject.uuid = UUID.randomUUID().toString();
        policyObject.body.dataAttributes = new ArrayList<>(attributes.size());
        policyObject.body.dissem = new ArrayList<>();

        for (String attribute : attributes) {
            PolicyObject.AttributeObject attributeObject = new PolicyObject.AttributeObject();
            attributeObject.attribute = attribute;
            policyObject.body.dataAttributes.add(attributeObject);
        }
        return policyObject;
    }

    public static class CollectionKey {
        private final byte[] key;
    
        public CollectionKey(byte[] key) {
            this.key = key;
        }
        protected byte[] getKey() {
            return key;
        }
    }
}
