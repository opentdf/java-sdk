package io.opentdf.platform.sdk;

import com.connectrpc.ResponseMessageKt;
import io.opentdf.platform.generated.policy.kasregistry.KeyAccessServerRegistryServiceClient;
import io.opentdf.platform.generated.policy.kasregistry.ListKeyAccessServersRequest;
import io.opentdf.platform.generated.policy.kasregistry.ListKeyAccessServersResponse;
import io.opentdf.platform.sdk.TDF.KasAllowlistException;
import io.opentdf.platform.sdk.nanotdf.*;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.concurrent.ExecutionException;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The NanoTDF class provides methods to create and read NanoTDF (Tiny Data Format) files.
 * The NanoTDF format is intended for securely encrypting small data payloads using elliptic-curve cryptography
 * and authenticated encryption.
 */
public class NanoTDF {

    public static Logger logger = LoggerFactory.getLogger(NanoTDF.class);

    public static final byte[] MAGIC_NUMBER_AND_VERSION = new byte[] { 0x4C, 0x31, 0x4C };
    private static final int kMaxTDFSize = ((16 * 1024 * 1024) - 3 - 32); // 16 mb - 3(iv) - 32(max auth tag)
    private static final int kNanoTDFGMACLength = 8;
    private static final int kIvPadding = 9;
    private static final int kNanoTDFIvSize = 3;
    private static final byte[] kEmptyIV = new byte[] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
    private final CollectionStore collectionStore;

    public NanoTDF() {
        this(new CollectionStore.NoOpCollectionStore());
    }

    public NanoTDF(boolean collectionStoreEnabled) {
        this(collectionStoreEnabled ? new CollectionStoreImpl() : null);
    }

    public NanoTDF(CollectionStore collectionStore) {
        this.collectionStore = collectionStore;
    }

    public static class NanoTDFMaxSizeLimit extends Exception {
        public NanoTDFMaxSizeLimit(String errorMessage) {
            super(errorMessage);
        }
    }

    public static class UnsupportedNanoTDFFeature extends Exception {
        public UnsupportedNanoTDFFeature(String errorMessage) {
            super(errorMessage);
        }
    }

    public static class InvalidNanoTDFConfig extends Exception {
        public InvalidNanoTDFConfig(String errorMessage) {
            super(errorMessage);
        }
    }

    private Config.HeaderInfo getHeaderInfo(Config.NanoTDFConfig nanoTDFConfig, SDK.KAS kas)
            throws InvalidNanoTDFConfig, UnsupportedNanoTDFFeature, NoSuchAlgorithmException, InterruptedException {
        if (nanoTDFConfig.collectionConfig.useCollection) {
            Config.HeaderInfo headerInfo = nanoTDFConfig.collectionConfig.getHeaderInfo();
            if (headerInfo != null) {
                return headerInfo;
            }
        }

        Gson gson = new GsonBuilder().create();
        if (nanoTDFConfig.kasInfoList.isEmpty()) {
            throw new InvalidNanoTDFConfig("kas url is missing");
        }

        Config.KASInfo kasInfo = nanoTDFConfig.kasInfoList.get(0);
        String url = kasInfo.URL;
        if (kasInfo.PublicKey == null || kasInfo.PublicKey.isEmpty()) {
            logger.info("no public key provided for KAS at {}, retrieving", url);
            kasInfo = kas.getECPublicKey(kasInfo, nanoTDFConfig.eccMode.getEllipticCurveType());
        }

        // Kas url resource locator
        ResourceLocator kasURL = new ResourceLocator(nanoTDFConfig.kasInfoList.get(0).URL, kasInfo.KID);
        assert kasURL.getIdentifier() != null : "Identifier in ResourceLocator cannot be null";

        ECKeyPair keyPair = new ECKeyPair(nanoTDFConfig.eccMode.getCurveName(), ECKeyPair.ECAlgorithm.ECDSA);

        // Generate symmetric key
        ECPublicKey kasPublicKey = ECKeyPair.publicKeyFromPem(kasInfo.PublicKey);
        byte[] symmetricKey = ECKeyPair.computeECDHKey(kasPublicKey, keyPair.getPrivateKey());

        // Generate HKDF key
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashOfSalt = digest.digest(MAGIC_NUMBER_AND_VERSION);
        byte[] key = ECKeyPair.calculateHKDF(hashOfSalt, symmetricKey);

        // Encrypt policy
        PolicyObject policyObject = createPolicyObject(nanoTDFConfig.attributes);
        String policyObjectAsStr = gson.toJson(policyObject);

        logger.debug("createNanoTDF policy object - {}", policyObjectAsStr);

        AesGcm gcm = new AesGcm(key);
        byte[] policyObjectAsBytes = policyObjectAsStr.getBytes(StandardCharsets.UTF_8);
        int authTagSize = SymmetricAndPayloadConfig.sizeOfAuthTagForCipher(nanoTDFConfig.config.getCipherType());
        byte[] encryptedPolicy = gcm.encrypt(kEmptyIV, authTagSize, policyObjectAsBytes, 0, policyObjectAsBytes.length);

        PolicyInfo policyInfo = new PolicyInfo();
        byte[] encryptedPolicyWithoutIV = Arrays.copyOfRange(encryptedPolicy, kEmptyIV.length, encryptedPolicy.length);
        policyInfo.setEmbeddedEncryptedTextPolicy(encryptedPolicyWithoutIV);

        if (nanoTDFConfig.eccMode.isECDSABindingEnabled()) {
            throw new UnsupportedNanoTDFFeature("ECDSA policy binding is not support");
        } else {
            byte[] hash = digest.digest(encryptedPolicyWithoutIV);
            byte[] gmac = Arrays.copyOfRange(hash, hash.length - kNanoTDFGMACLength,
                    hash.length);
            policyInfo.setPolicyBinding(gmac);
        }

        // Create header
        byte[] compressedPubKey = keyPair.compressECPublickey();
        Header header = new Header();
        header.setECCMode(nanoTDFConfig.eccMode);
        header.setPayloadConfig(nanoTDFConfig.config);
        header.setEphemeralKey(compressedPubKey);
        header.setKasLocator(kasURL);
        header.setPolicyInfo(policyInfo);

        Config.HeaderInfo headerInfo = new Config.HeaderInfo(header, gcm, 0);
        if (nanoTDFConfig.collectionConfig.useCollection) {
            nanoTDFConfig.collectionConfig.updateHeaderInfo(headerInfo);
        }

        return headerInfo;
    }

    public int createNanoTDF(ByteBuffer data, OutputStream outputStream,
            Config.NanoTDFConfig nanoTDFConfig,
            SDK.KAS kas) throws IOException, NanoTDFMaxSizeLimit, InvalidNanoTDFConfig,
            NoSuchAlgorithmException, UnsupportedNanoTDFFeature, InterruptedException {
        int nanoTDFSize = 0;

        int dataSize = data.limit();
        if (dataSize > kMaxTDFSize) {
            throw new NanoTDFMaxSizeLimit("exceeds max size for nano tdf");
        }

        Config.HeaderInfo headerKeyPair = getHeaderInfo(nanoTDFConfig, kas);
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

        int authTagSize = SymmetricAndPayloadConfig.sizeOfAuthTagForCipher(nanoTDFConfig.config.getCipherType());
        // Encrypt the data
        byte[] actualIV = new byte[kIvPadding + kNanoTDFIvSize];
        if (nanoTDFConfig.collectionConfig.useCollection) {
            ByteBuffer b = ByteBuffer.allocate(4);
            b.order(ByteOrder.LITTLE_ENDIAN);
            b.putInt(iteration);
            System.arraycopy(b.array(), 0, actualIV, kIvPadding, kNanoTDFIvSize);
        } else {
            do {
                byte[] iv = new byte[kNanoTDFIvSize];
                SecureRandom.getInstanceStrong().nextBytes(iv);
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

    public void readNanoTDF(ByteBuffer nanoTDF, OutputStream outputStream,
            SDK.KAS kas) throws IOException, URISyntaxException {
             readNanoTDF(nanoTDF, outputStream,kas, Config.newNanoTDFReaderConfig());
    }

    public void readNanoTDF(ByteBuffer nanoTDF, OutputStream outputStream,
                            SDK.KAS kas, KeyAccessServerRegistryServiceClient kasRegistryService, String platformUrl) throws IOException, InterruptedException, ExecutionException, URISyntaxException {
             readNanoTDF(nanoTDF, outputStream,kas, Config.newNanoTDFReaderConfig(), kasRegistryService, platformUrl);
    }

    public void readNanoTDF(ByteBuffer nanoTDF, OutputStream outputStream,
            SDK.KAS kas, Config.NanoTDFReaderConfig nanoTdfReaderConfig, KeyAccessServerRegistryServiceClient kasRegistryService, String platformUrl) throws IOException, InterruptedException, ExecutionException, URISyntaxException {
        if (!nanoTdfReaderConfig.ignoreKasAllowlist && (nanoTdfReaderConfig.kasAllowlist == null || nanoTdfReaderConfig.kasAllowlist.isEmpty())) {
            ListKeyAccessServersRequest request = ListKeyAccessServersRequest.newBuilder()
                    .build();
            ListKeyAccessServersResponse response = ResponseMessageKt.getOrThrow(kasRegistryService.listKeyAccessServersBlocking(request, Collections.emptyMap()).execute());
            nanoTdfReaderConfig.kasAllowlist = new HashSet<>();
            var kases = response.getKeyAccessServersList();

            for (var entry : kases) {
                nanoTdfReaderConfig.kasAllowlist.add(Config.getKasAddress(entry.getUri()));
            }

            nanoTdfReaderConfig.kasAllowlist.add(Config.getKasAddress(platformUrl));
        }
        readNanoTDF(nanoTDF, outputStream, kas, nanoTdfReaderConfig);
    }


    public void readNanoTDF(ByteBuffer nanoTDF, OutputStream outputStream,
            SDK.KAS kas, Config.NanoTDFReaderConfig nanoTdfReaderConfig) throws IOException, URISyntaxException {

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
            if (nanoTdfReaderConfig.ignoreKasAllowlist) {
                logger.warn("Ignoring KasAllowlist for url {}", realAddress);
            } else if (nanoTdfReaderConfig.kasAllowlist == null || nanoTdfReaderConfig.kasAllowlist.isEmpty()) {
                logger.error("KasAllowlist: No KAS allowlist provided and no KeyAccessServerRegistry available, {} is not allowed", realAddress);
                throw new KasAllowlistException("No KAS allowlist provided and no KeyAccessServerRegistry available");
            } else if (!nanoTdfReaderConfig.kasAllowlist.contains(realAddress)) {
                logger.error("KasAllowlist: kas url {} is not allowed", realAddress);
                throw new KasAllowlistException("KasAllowlist: kas url "+realAddress+" is not allowed");
            }


            key = kas.unwrapNanoTDF(header.getECCMode().getEllipticCurveType(),
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
