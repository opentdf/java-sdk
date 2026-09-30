package io.opentdf.platform.sdk;

import com.connectrpc.ConnectException;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.nimbusds.jose.*;

import io.opentdf.platform.policy.kasregistry.ListKeyAccessServersRequest;
import io.opentdf.platform.policy.kasregistry.ListKeyAccessServersResponse;
import io.opentdf.platform.sdk.Config.KASInfo;
import io.opentdf.platform.sdk.spi.KemProviders;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.*;

/**
 * The TDF class is responsible for handling operations related to
 * Trusted Data Format (TDF). It includes methods to create and load
 * TDF objects, as well as utility functions to handle cryptographic
 * operations and configurations.
 */
class TDF {

    private static byte[] tdfECKeySaltCompute() {
        byte[] salt;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update("TDF".getBytes());
            salt = digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("failed to compute salt for TDF", e);
        }
        return salt;
    }

    public static final byte[] GLOBAL_KEY_SALT = tdfECKeySaltCompute();
    static final String EMPTY_SPLIT_ID = ""; // Made package-private for TDFTest usage if needed, or could be private if
                                             // not used by TDFTest
    /**
     * The TDF specification version this SDK implements.
     */
    public static final String TDF_SPEC_VERSION = "4.3.0";
    private static final String KEY_ACCESS_SCHEMA_VERSION = "1.0";
    private final SDK.Services services;

    TDF(SDK.Services services) {
        this.services = services;
    }

    private static final Logger logger = LoggerFactory.getLogger(TDF.class);

    private static final int GCM_KEY_SIZE = 32;
    private static final String kSplitKeyType = "split";
    private static final String kWrapped = "wrapped";
    private static final String kECWrapped = "ec-wrapped";
    private static final String kHybridWrapped = "hybrid-wrapped";
    private static final String kMlkemWrapped = "mlkem-wrapped";
    private static final String kKasProtocol = "kas";
    private static final int kGcmIvSize = 12;
    private static final String kGCMCipherAlgorithm = "AES-256-GCM";
    private static final int kGMACPayloadLength = 16;
    private static final String kGmacIntegrityAlgorithm = "GMAC";

    private static final String kHmacIntegrityAlgorithm = "HS256";
    private static final String kTDFAsZip = "zip";
    private static final String kTDFZipReference = "reference";

    private static final Gson gson = new GsonBuilder().create();

    static final class IvCounter {
        static final int FIXED_FIELD_SIZE = 8;
        static final long MAX_INVOCATION = 0xffff_ffffL;

        private final byte[] fixedField;
        private long nextInvocation;
        private boolean exhausted;

        IvCounter() {
            this(generateFixedField(), 0);
        }

        IvCounter(byte[] fixedField, long initialInvocation) {
            Objects.requireNonNull(fixedField, "fixed field");
            if (fixedField.length != FIXED_FIELD_SIZE) {
                throw new IllegalArgumentException("invalid IV fixed field size: " + fixedField.length);
            }
            if (initialInvocation < 0 || initialInvocation > MAX_INVOCATION) {
                throw new IllegalArgumentException("invalid IV invocation: " + initialInvocation);
            }
            this.fixedField = fixedField.clone();
            this.nextInvocation = initialInvocation;
        }

        synchronized byte[] next() {
            if (exhausted) {
                throw new SDKException("AES-GCM IV invocation field exhausted; output stream is incomplete");
            }

            long invocation = nextInvocation;
            if (invocation == MAX_INVOCATION) {
                exhausted = true;
            } else {
                nextInvocation++;
            }

            byte[] iv = new byte[kGcmIvSize];
            System.arraycopy(fixedField, 0, iv, 0, FIXED_FIELD_SIZE);
            iv[8] = (byte) (invocation >>> 24);
            iv[9] = (byte) (invocation >>> 16);
            iv[10] = (byte) (invocation >>> 8);
            iv[11] = (byte) invocation;
            return iv;
        }

        private static byte[] generateFixedField() {
            byte[] fixedField = new byte[FIXED_FIELD_SIZE];
            try {
                SecureRandom.getInstanceStrong().nextBytes(fixedField);
            } catch (NoSuchAlgorithmException e) {
                throw new SDKException("error generating IV fixed field", e);
            }
            return fixedField;
        }
    }

    static class EncryptedMetadata {
        private String ciphertext;
        private String iv;
    }

    static class ECKeyWrappedKeyInfo {
        private String publicKey;
        private String wrappedKey;
    }

    static class TDFObject {
        public Manifest getManifest() {
            return manifest;
        }

        private Manifest manifest;
        private long size;
        private AesGcm aesGcm;
        private final byte[] payloadKey = new byte[GCM_KEY_SIZE];

        public TDFObject() {
            this.manifest = new Manifest();
            this.manifest.encryptionInformation = new Manifest.EncryptionInformation();
            this.manifest.encryptionInformation.integrityInformation = new Manifest.IntegrityInformation();
            this.manifest.encryptionInformation.method = new Manifest.Method();
            this.size = 0;
        }

        private PolicyObject createPolicyObject(List<Autoconfigure.AttributeValueFQN> attributes) {
            PolicyObject policyObject = new PolicyObject();
            policyObject.body = new PolicyObject.Body();
            policyObject.uuid = UUID.randomUUID().toString();
            policyObject.body.dataAttributes = new ArrayList<>(attributes.size());
            policyObject.body.dissem = new ArrayList<>();

            for (Autoconfigure.AttributeValueFQN attribute : attributes) {
                PolicyObject.AttributeObject attributeObject = new PolicyObject.AttributeObject();
                attributeObject.attribute = attribute.toString();
                policyObject.body.dataAttributes.add(attributeObject);
            }
            return policyObject;
        }

        private static final Base64.Encoder encoder = Base64.getEncoder();

        private void prepareManifest(Config.TDFConfig tdfConfig, Map<String, List<KASInfo>> splits,
                byte[] metadataIv) {
            manifest.tdfVersion = tdfConfig.renderVersionInfoInManifest ? TDF_SPEC_VERSION : null;
            manifest.encryptionInformation.keyAccessType = kSplitKeyType;
            manifest.encryptionInformation.keyAccessObj = new ArrayList<>();

            PolicyObject policyObject = createPolicyObject(tdfConfig.attributes);
            String base64PolicyObject = encoder
                    .encodeToString(gson.toJson(policyObject).getBytes(StandardCharsets.UTF_8));


            List<byte[]> symKeys = new ArrayList<>(splits.size());
            for (var split : splits.entrySet()) {
                String splitID = split.getKey();

                // Symmetric key
                byte[] symKey = AesGcm.generateKey();
                symKeys.add(symKey);

                // Add policyBinding
                var hexBinding = Hex.encodeHexString(
                        CryptoUtils.CalculateSHA256Hmac(symKey, base64PolicyObject.getBytes(StandardCharsets.UTF_8)));
                var policyBinding = new Manifest.PolicyBinding();
                policyBinding.alg = kHmacIntegrityAlgorithm;
                policyBinding.hash = encoder.encodeToString(hexBinding.getBytes(StandardCharsets.UTF_8));

                // Add meta data
                var encryptedMetadata = "";
                if (tdfConfig.metaData != null && !tdfConfig.metaData.trim().isEmpty()) {
                    byte[] metaBytes = tdfConfig.metaData.getBytes(StandardCharsets.UTF_8);
                    AesGcm aesGcm = new AesGcm(symKey);
                    byte[] ivAndCiphertext = aesGcm.encrypt(metadataIv, AesGcm.GCM_TAG_LENGTH, metaBytes, 0, metaBytes.length);

                    EncryptedMetadata em = new EncryptedMetadata();
                    em.iv = encoder.encodeToString(metadataIv);
                    em.ciphertext = encoder.encodeToString(ivAndCiphertext);

                    var metadata = gson.toJson(em);
                    encryptedMetadata = encoder.encodeToString(metadata.getBytes(StandardCharsets.UTF_8));
                }

                List<KASInfo> kasInfos = split.getValue();
                for (Config.KASInfo kasInfo : kasInfos) {
                    if (kasInfo.PublicKey == null || kasInfo.PublicKey.isEmpty()) {
                        throw new SDK.KasPublicKeyMissing("Kas public key is missing in kas information list");
                    }

                    var keyAccess = createKeyAccess(tdfConfig, kasInfo, symKey, policyBinding, encryptedMetadata,
                            splitID);
                    manifest.encryptionInformation.keyAccessObj.add(keyAccess);
                }
            }

            manifest.encryptionInformation.policy = base64PolicyObject;
            manifest.encryptionInformation.method.algorithm = kGCMCipherAlgorithm;

            // Create the payload key by XOR all the keys in key access object.
            for (byte[] symKey : symKeys) {
                for (int index = 0; index < symKey.length; index++) {
                    this.payloadKey[index] ^= symKey[index];
                }
            }

            this.aesGcm = new AesGcm(this.payloadKey);
        }

        private Manifest.KeyAccess createKeyAccess(Config.TDFConfig tdfConfig, Config.KASInfo kasInfo, byte[] symKey,
                Manifest.PolicyBinding policyBinding, String encryptedMetadata, String splitID) {
            Manifest.KeyAccess keyAccess = new Manifest.KeyAccess();
            keyAccess.keyType = kWrapped;
            keyAccess.url = kasInfo.URL;
            keyAccess.kid = kasInfo.KID;
            keyAccess.protocol = kKasProtocol;
            keyAccess.policyBinding = policyBinding;
            keyAccess.encryptedMetadata = encryptedMetadata;
            keyAccess.sid = splitID;
            keyAccess.schemaVersion = KEY_ACCESS_SCHEMA_VERSION;

            var algorithm = kasInfo.Algorithm == null || kasInfo.Algorithm.isEmpty()
                    ? tdfConfig.wrappingKeyType.toString()
                    : kasInfo.Algorithm;

            var keyType = KeyType.fromString(algorithm);
            if (keyType.isHybrid()) {
                // Dispatch to whichever KemProvider claims this KeyType (typically the
                // BouncyCastle-backed impl in sdk-pqc-bc). Keeps the core sdk jar free
                // of BC compile-time references so the fips Maven profile stays clean.
                byte[] wrapped = KemProviders.get(keyType).wrapDEK(keyType, kasInfo.PublicKey, symKey);
                keyAccess.wrappedKey = Base64.getEncoder().encodeToString(wrapped);
                keyAccess.keyType = kHybridWrapped;
                // ephemeralPublicKey intentionally left null — the ephemeral material is
                // carried inside the ASN.1 envelope in wrappedKey.
            } else if (keyType.isMLKEM()) {
                // Pure ML-KEM (FIPS 203). Same KemProviders dispatch and same ASN.1
                // envelope as hybrid, but its own KAO scheme ("mlkem-wrapped") so the
                // KAS knows to skip HKDF on the wrap-key derivation — see
                // platform PR #3562 and adr/decisions/2026-06-16-mlkem-direct-key-wrap.md.
                byte[] wrapped = KemProviders.get(keyType).wrapDEK(keyType, kasInfo.PublicKey, symKey);
                keyAccess.wrappedKey = Base64.getEncoder().encodeToString(wrapped);
                keyAccess.keyType = kMlkemWrapped;
            } else if (keyType.isEc()) {
                var ecKeyWrappedKeyInfo = createECWrappedKey(kasInfo, symKey, keyType);
                keyAccess.wrappedKey = ecKeyWrappedKeyInfo.wrappedKey;
                keyAccess.ephemeralPublicKey = ecKeyWrappedKeyInfo.publicKey;
                keyAccess.keyType = kECWrapped;
            } else {
                keyAccess.wrappedKey = createRSAWrappedKey(kasInfo, symKey);
                keyAccess.keyType = kWrapped;
            }
            return keyAccess;
        }

        private ECKeyWrappedKeyInfo createECWrappedKey(Config.KASInfo kasInfo,
                byte[] symKey, KeyType keyType) {
            var curveName = keyType.getECCurve();
            var keyPair = new ECKeyPair(curveName);

            ECPublicKey kasPubKey;
            try {
                kasPubKey = ECKeyPair.publicKeyFromPem(kasInfo.PublicKey);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new SDKException("error decoding KAS EC public key", e);
            }
            byte[] symmetricKey = ECKeyPair.computeECDHKey(kasPubKey, keyPair.getPrivateKey());

            var sessionKey = ECKeyPair.calculateHKDF(GLOBAL_KEY_SALT, symmetricKey);

            AesGcm gcm = new AesGcm(sessionKey);
            AesGcm.Encrypted wrappedKey = gcm.encrypt(symKey);

            ECKeyWrappedKeyInfo wrappedKeyInfo = new ECKeyWrappedKeyInfo();
            wrappedKeyInfo.publicKey = keyPair.publicKeyInPEMFormat();
            wrappedKeyInfo.wrappedKey = Base64.getEncoder().encodeToString(wrappedKey.asBytes());
            return wrappedKeyInfo;
        }

        private String createRSAWrappedKey(Config.KASInfo kasInfo, byte[] symKey) {
            AsymEncryption asymEncrypt = new AsymEncryption(kasInfo.PublicKey);
            byte[] wrappedKey = asymEncrypt.encrypt(symKey);
            return Base64.getEncoder().encodeToString(wrappedKey);
        }
    }

    private static final Base64.Decoder decoder = Base64.getDecoder();

    public static class Reader {
        private final TDFReader tdfReader;
        private final byte[] payloadKey;
        private final Manifest manifest;

        public String getMetadata() {
            return unencryptedMetadata;
        }

        public Manifest getManifest() {
            return manifest;
        }

        private final String unencryptedMetadata;
        private final AesGcm aesGcm;

        Reader(TDFReader tdfReader, Manifest manifest, byte[] payloadKey, String unencryptedMetadata) {
            this.tdfReader = tdfReader;
            this.manifest = manifest;
            this.aesGcm = new AesGcm(payloadKey);
            this.payloadKey = payloadKey;
            this.unencryptedMetadata = unencryptedMetadata;
        }

        public void readPayload(OutputStream outputStream) throws SDK.TamperException, IOException {

            MessageDigest digest = null;
            try {
                digest = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("error getting instance of SHA-256", e);
            }

            validateSegmentSizes();

            for (Manifest.Segment segment : manifest.encryptionInformation.integrityInformation.segments) {
                byte[] readBuf = new byte[(int) segment.encryptedSegmentSize];
                int bytesRead = tdfReader.readPayloadBytes(readBuf);

                if (readBuf.length != bytesRead) {
                    throw new IllegalStateException("unable to read bytes for segment (wanted "
                            + segment.encryptedSegmentSize + " but got " + bytesRead + ")");
                }

                var isLegacyTdf = manifest.tdfVersion == null || manifest.tdfVersion.isEmpty();

                if (manifest.payload.isEncrypted) {
                    var sigAlg = segmentIntegrityAlgorithmFromManifest(
                            manifest.encryptionInformation.integrityInformation.segmentHashAlg);

                    var payloadSig = segmentIntegrity(readBuf, payloadKey, sigAlg);
                    if (isLegacyTdf) {
                        payloadSig = Hex.encodeHexString(payloadSig).getBytes(StandardCharsets.UTF_8);
                    }

                    if (segment.hash.compareTo(Base64.getEncoder().encodeToString(payloadSig)) != 0) {
                        throw new SDK.SegmentSignatureMismatch("segment signature miss match");
                    }

                    byte[] writeBuf = aesGcm.decrypt(new AesGcm.Encrypted(readBuf));
                    outputStream.write(writeBuf);

                } else {
                    String segmentSig = Hex.encodeHexString(digest.digest(readBuf));
                    if (segment.hash.compareTo(segmentSig) != 0) {
                        throw new SDK.SegmentSignatureMismatch("segment signature miss match");
                    }

                    outputStream.write(readBuf);
                }
            }
        }

        /**
         * Rejects segment sizes that cannot describe a real segment, before any of the payload is
         * decrypted. Run as a pre-pass so an invalid size on a later segment does not leave the
         * caller holding the plaintext of the earlier ones.
         * <p>
         * A too-small size otherwise reaches the integrity check as an unrelated signature
         * mismatch, or under GMAC as a complaint about the payload being too small to hash. A
         * negative one reaches {@code new byte[...]} as a {@link NegativeArraySizeException}.
         */
        private void validateSegmentSizes() {
            // an encrypted segment carries an IV and an auth tag on top of its plaintext, so it
            // can never be shorter than the two of them together. an unencrypted payload is stored
            // as-is, where the only impossible length is a non-positive one
            long minEncryptedSegmentSize = manifest.payload.isEncrypted ? kGcmIvSize + AesGcm.GCM_TAG_LENGTH : 1;

            List<Manifest.Segment> segments = manifest.encryptionInformation.integrityInformation.segments;
            for (int i = 0; i < segments.size(); i++) {
                long encryptedSegmentSize = segments.get(i).encryptedSegmentSize;

                if (encryptedSegmentSize < minEncryptedSegmentSize) {
                    throw new IllegalStateException("invalid TDF: segment " + i
                            + " declares an encryptedSegmentSize of " + encryptedSegmentSize
                            + ", but a segment of this payload cannot be shorter than "
                            + minEncryptedSegmentSize + " bytes");
                }

                if (encryptedSegmentSize > Config.MAX_SEGMENT_SIZE) {
                    throw new IllegalStateException("Segment size " + encryptedSegmentSize + " exceeded limit "
                            + Config.MAX_SEGMENT_SIZE);
                } // MIN_SEGMENT_SIZE NOT validated out due to tests needing small segment sizes
                  // with existing payloads
            }
        }

        public PolicyObject readPolicyObject() {
            return tdfReader.readPolicyObject();
        }

        /**
         * Resolves {@code segmentHashAlg} as read from the manifest. Both algorithms are
         * allowed: a GMAC segment hash proves nothing by itself, but unlike the root it is
         * bracketed by keyed checks that do (see {@link TDF#aeadTag}). An unrecognized name
         * is still refused rather than defaulted. Contrast
         * {@link TDF#rootIntegrityAlgorithmFromManifest}, where only HS256 is meaningful.
         */
        private static Config.IntegrityAlgorithm segmentIntegrityAlgorithmFromManifest(String declared) {
            if (declared != null) {
                String name = declared.trim();
                if (kGmacIntegrityAlgorithm.equalsIgnoreCase(name)) {
                    return Config.IntegrityAlgorithm.GMAC;
                }
                if (kHmacIntegrityAlgorithm.equalsIgnoreCase(name)) {
                    return Config.IntegrityAlgorithm.HS256;
                }
            }
            // Not a SegmentSignatureMismatch: no signature was compared. Still a
            // TamperException, because segmentHashAlg is not covered by the root
            // signature and so is something an attacker can freely rewrite.
            throw new SDK.TamperException("unsupported segment integrity algorithm: " + declared);
        }
    }

    /**
     * Recovers the trailing AES-GCM authentication tag from a segment's ciphertext.
     * <p>
     * Recovering a tag is not verifying one. These are bytes whoever supplied the input
     * already holds, so comparing them against a manifest value is keyless and on its own
     * proves nothing — an attacker can re-chunk a payload and write each chunk's own
     * trailing sixteen bytes into its {@code segment.hash}. What makes a GMAC segment hash
     * trustworthy is the keyed checks around it: {@code loadTDF} has already validated the
     * whole list of segment hashes against the HS256 root signature, and {@code readPayload}
     * follows the comparison with a real AES-GCM tag check under the payload key.
     * <p>
     * The root signature has neither backstop — it is the outermost check, so a "GMAC root"
     * is a keyless comparison with nothing behind it. The asymmetry is therefore structural,
     * not a property of the bytes, and it is why {@link #rootIntegrity} does not offer this
     * algorithm.
     */
    private static byte[] aeadTag(byte[] ciphertext) {
        if (kGMACPayloadLength > ciphertext.length) {
            throw new IllegalArgumentException("tried to calculate GMAC on too small a payload. payload is "
                    + ciphertext.length + " bytes while GMAC is " + kGMACPayloadLength + " bytes");
        }

        return Arrays.copyOfRange(ciphertext, ciphertext.length - kGMACPayloadLength, ciphertext.length);
    }

    /**
     * The integrity value recorded in a segment's {@code hash}.
     *
     * @param ciphertext the AES-GCM output for this segment, whole and unmodified
     * @param key        the payload key
     * @param algorithm  {@code GMAC} to reuse the segment's own AEAD tag, or
     *                   {@code HS256} to HMAC the segment ciphertext
     * @throws IllegalArgumentException if {@code algorithm} is null or unsupported
     */
    static byte[] segmentIntegrity(byte[] ciphertext, byte[] key, Config.IntegrityAlgorithm algorithm) {
        requireSupportedSegmentIntegrityAlgorithm(algorithm);
        switch (algorithm) {
            case HS256:
                return CryptoUtils.CalculateSHA256Hmac(key, ciphertext);
            case GMAC:
                return aeadTag(ciphertext);
            default:
                throw new IllegalArgumentException("unsupported segment integrity algorithm: " + algorithm);
        }
    }

    /**
     * The integrity value recorded in {@code rootSignature.sig}, over the concatenated
     * segment hashes.
     * <p>
     * HS256 only. The aggregate hash never passes through the AEAD, so there is no tag
     * to recover from it; a "GMAC" root signature is just a copy of the last segment
     * hash, which is attacker-controlled manifest data. Accepting one would let anyone
     * truncate, reorder, duplicate or drop segments without holding a key, since nothing
     * else binds a segment to its index or to the segment count.
     *
     * @throws IllegalArgumentException if {@code algorithm} is anything but HS256
     */
    static byte[] rootIntegrity(byte[] aggregateHash, byte[] key, Config.IntegrityAlgorithm algorithm) {
        requireSupportedRootIntegrityAlgorithm(algorithm);
        return CryptoUtils.CalculateSHA256Hmac(key, aggregateHash);
    }

    /**
     * The segment counterpart to {@link #requireSupportedRootIntegrityAlgorithm}. Both
     * algorithms are legal in this position, so this exists to reject {@code null} and any
     * future enum value in {@code createTDF} rather than partway through the payload:
     * TDFConfig's fields are public, so a field left unset arrives here as {@code null} and
     * would otherwise surface as a {@link NullPointerException} at the switch below, after
     * segments had already been written to the output stream.
     *
     * @throws IllegalArgumentException if {@code algorithm} cannot hash a segment
     */
    static void requireSupportedSegmentIntegrityAlgorithm(Config.IntegrityAlgorithm algorithm) {
        if (algorithm != Config.IntegrityAlgorithm.HS256 && algorithm != Config.IntegrityAlgorithm.GMAC) {
            throw new IllegalArgumentException("unsupported segment integrity algorithm: " + algorithm);
        }
    }

    /**
     * The write-path gate, and a second checkpoint inside {@link #rootIntegrity}.
     * <p>
     * An {@link IllegalArgumentException} rather than a {@link SDK.TamperException}, on
     * purpose. Reading, this is unreachable: {@link #rootIntegrityAlgorithmFromManifest}
     * has already narrowed the manifest's declaration to HS256 or thrown
     * {@link SDK.RootSignatureValidationException} trying. So if it ever does fire on a
     * read, the cause is a bug in this class rather than a hostile file, and it should
     * escape {@code loadTDF} uncaught instead of being reported to callers as tamper —
     * fail loud, and do not let a defect hide inside an exception type that callers
     * routinely handle.
     *
     * @throws IllegalArgumentException if {@code algorithm} cannot authenticate a root
     *                                  signature
     */
    static void requireSupportedRootIntegrityAlgorithm(Config.IntegrityAlgorithm algorithm) {
        if (algorithm != Config.IntegrityAlgorithm.HS256) {
            throw new IllegalArgumentException("unsupported root integrity algorithm: " + algorithm
                    + "; the root signature must be " + kHmacIntegrityAlgorithm);
        }
    }

    /**
     * Resolves {@code rootSignature.alg} as read from the (unauthenticated) manifest.
     * <p>
     * An allowlist, deliberately: anything other than HS256 — GMAC, an unknown name, an
     * empty string — is refused rather than being defaulted to HS256. Defaulting would
     * validate a downgraded manifest against an algorithm it does not declare.
     */
    private static Config.IntegrityAlgorithm rootIntegrityAlgorithmFromManifest(String declared) {
        if (declared != null && kHmacIntegrityAlgorithm.equalsIgnoreCase(declared.trim())) {
            return Config.IntegrityAlgorithm.HS256;
        }
        throw new SDK.RootSignatureValidationException("unsupported root integrity algorithm: " + declared
                + "; the root signature must be " + kHmacIntegrityAlgorithm);
    }

    /**
     * @throws IllegalArgumentException if {@code tdfConfig} selects an integrity algorithm
     *                                  that cannot be written. Unchecked and not an
     *                                  {@link SDKException}, matching how the config layer
     *                                  already reports out-of-range values (see
     *                                  {@link Config#withSegmentSize}): this is a caller
     *                                  mistake to fix in code, not a condition to handle
     *                                  alongside I/O and tamper failures.
     */
    TDFObject createTDF(InputStream payload, OutputStream outputStream, Config.TDFConfig tdfConfig) throws SDKException, IOException {
        // Checked before anything is written so an unusable algorithm cannot produce a
        // partial TDF. There are no setters for these -- the config defaults to an HS256
        // root and GMAC segments -- but TDFConfig's fields are public, so re-check what
        // was actually set.
        requireSupportedRootIntegrityAlgorithm(tdfConfig.integrityAlgorithm);
        requireSupportedSegmentIntegrityAlgorithm(tdfConfig.segmentIntegrityAlgorithm);

        Planner planner = new Planner(tdfConfig, services, Autoconfigure::createGranter);
        Map<String, List<KASInfo>> splits = planner.getSplits();

        // Add System Metadata Assertion if configured
        if (tdfConfig.systemMetadataAssertion) {
            AssertionConfig systemAssertion = AssertionConfig.getSystemMetadataAssertionConfig(TDF_SPEC_VERSION);
            tdfConfig.assertionConfigList.add(systemAssertion);
        }

        TDFObject tdfObject = new TDFObject();
        IvCounter streamIv = new IvCounter();
        byte[] metadataIv = streamIv.next();
        tdfObject.prepareManifest(tdfConfig, splits, metadataIv);

        long encryptedSegmentSize = (long) tdfConfig.defaultSegmentSize + kGcmIvSize + AesGcm.GCM_TAG_LENGTH;
        TDFWriter tdfWriter = new TDFWriter(outputStream);

        ByteArrayOutputStream aggregateHash = new ByteArrayOutputStream();
        byte[] readBuf = new byte[tdfConfig.defaultSegmentSize];

        tdfObject.manifest.encryptionInformation.integrityInformation.segments = new ArrayList<>();
        boolean finished;
        try (var payloadOutput = tdfWriter.payload()) {
            do {
                int nRead = 0;
                int readThisLoop = 0;
                while (readThisLoop < readBuf.length
                        && (nRead = payload.read(readBuf, readThisLoop, readBuf.length - readThisLoop)) > 0) {
                    readThisLoop += nRead;
                }
                finished = nRead < 0;

                byte[] cipherData;
                byte[] segmentSig;
                Manifest.Segment segmentInfo = new Manifest.Segment();

                // encrypt
                cipherData = tdfObject.aesGcm.encrypt(streamIv.next(), AesGcm.GCM_TAG_LENGTH,
                        readBuf, 0, readThisLoop);
                payloadOutput.write(cipherData);

                segmentSig = segmentIntegrity(cipherData, tdfObject.payloadKey, tdfConfig.segmentIntegrityAlgorithm);
                if (tdfConfig.hexEncodeRootAndSegmentHashes) {
                    segmentSig = Hex.encodeHexString(segmentSig).getBytes(StandardCharsets.UTF_8);
                }
                segmentInfo.hash = Base64.getEncoder().encodeToString(segmentSig);

                aggregateHash.write(segmentSig);
                segmentInfo.segmentSize = readThisLoop;
                segmentInfo.encryptedSegmentSize = cipherData.length;

                tdfObject.manifest.encryptionInformation.integrityInformation.segments.add(segmentInfo);
            } while (!finished);
        }

        Manifest.RootSignature rootSignature = new Manifest.RootSignature();

        byte[] rootSig = rootIntegrity(aggregateHash.toByteArray(), tdfObject.payloadKey,
                tdfConfig.integrityAlgorithm);
        byte[] encodedRootSig = tdfConfig.hexEncodeRootAndSegmentHashes
                ? Hex.encodeHexString(rootSig).getBytes(StandardCharsets.UTF_8)
                : rootSig;
        rootSignature.signature = Base64.getEncoder().encodeToString(encodedRootSig);

        // Unconditional. createTDF refuses any other root algorithm before a byte is
        // written and rootIntegrity would refuse it again; selecting on tdfConfig here
        // would leave a path that emits alg="GMAC" should either check ever be relaxed.
        rootSignature.algorithm = kHmacIntegrityAlgorithm;

        tdfObject.manifest.encryptionInformation.integrityInformation.rootSignature = rootSignature;
        tdfObject.manifest.encryptionInformation.integrityInformation.segmentSizeDefault = tdfConfig.defaultSegmentSize;
        tdfObject.manifest.encryptionInformation.integrityInformation.encryptedSegmentSizeDefault = (int) encryptedSegmentSize;

        tdfObject.manifest.encryptionInformation.integrityInformation.segmentHashAlg = kGmacIntegrityAlgorithm;
        if (tdfConfig.segmentIntegrityAlgorithm == Config.IntegrityAlgorithm.HS256) {
            tdfObject.manifest.encryptionInformation.integrityInformation.segmentHashAlg = kHmacIntegrityAlgorithm;
        }

        tdfObject.manifest.encryptionInformation.method.IsStreamable = true;

        // Add payload info
        tdfObject.manifest.payload = new Manifest.Payload();
        tdfObject.manifest.payload.mimeType = tdfConfig.mimeType;
        tdfObject.manifest.payload.protocol = kTDFAsZip;
        tdfObject.manifest.payload.type = kTDFZipReference;
        tdfObject.manifest.payload.url = TDFWriter.TDF_PAYLOAD_FILE_NAME;
        tdfObject.manifest.payload.isEncrypted = true;

        List<Manifest.Assertion> signedAssertions = new ArrayList<>(tdfConfig.assertionConfigList.size());

        for (var assertionConfig : tdfConfig.assertionConfigList) {
            var assertion = new Manifest.Assertion();
            assertion.id = assertionConfig.id != null && !assertionConfig.id.isEmpty() ? assertionConfig.id : UUID.randomUUID().toString();
            assertion.type = assertionConfig.type.toString();
            assertion.scope = assertionConfig.scope.toString();
            assertion.statement = assertionConfig.statement;
            assertion.appliesToState = assertionConfig.appliesToState.toString();

            var assertionHashAsHex = assertion.hash();
            byte[] assertionHash;
            if (tdfConfig.hexEncodeRootAndSegmentHashes) {
                assertionHash = assertionHashAsHex.getBytes(StandardCharsets.UTF_8);
            } else {
                try {
                    assertionHash = Hex.decodeHex(assertionHashAsHex);
                } catch (DecoderException e) {
                    throw new SDKException("error decoding assertion hash", e);
                }
            }
            byte[] completeHash = new byte[aggregateHash.size() + assertionHash.length];
            System.arraycopy(aggregateHash.toByteArray(), 0, completeHash, 0, aggregateHash.size());
            System.arraycopy(assertionHash, 0, completeHash, aggregateHash.size(), assertionHash.length);

            var encodedHash = Base64.getEncoder().encodeToString(completeHash);

            var assertionSigningKey = new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.HS256,
                    tdfObject.aesGcm.getKey());
            if (assertionConfig.signingKey != null && assertionConfig.signingKey.isDefined()) {
                assertionSigningKey = assertionConfig.signingKey;
            }
            var hashValues = new Manifest.Assertion.HashValues(
                    assertionHashAsHex,
                    encodedHash);
            try {
                assertion.sign(hashValues, assertionSigningKey);
            } catch (KeyLengthException e) {
                throw new SDKException("error signing assertion hash", e);
            }
            signedAssertions.add(assertion);
        }

        tdfObject.manifest.assertions = signedAssertions;
        String manifestAsStr = gson.toJson(tdfObject.manifest);

        tdfWriter.appendManifest(manifestAsStr);
        tdfObject.size = tdfWriter.finish();

        return tdfObject;
    }


    Reader loadTDF(SeekableByteChannel tdf, String platformUrl) throws SDKException, IOException {
        return loadTDF(tdf, Config.newTDFReaderConfig(), platformUrl);
    }

    Reader loadTDF(SeekableByteChannel tdf, Config.TDFReaderConfig tdfReaderConfig, String platformUrl)
            throws SDKException, IOException {
        if (!tdfReaderConfig.ignoreKasAllowlist
                && (tdfReaderConfig.kasAllowlist == null || tdfReaderConfig.kasAllowlist.isEmpty())) {
            ListKeyAccessServersRequest request = ListKeyAccessServersRequest.newBuilder()
                    .build();
            ListKeyAccessServersResponse response;
            try {
                response = RequestHelper.getOrThrow(
                        services.kasRegistry().listKeyAccessServersBlocking(request, Collections.emptyMap()).execute());
            } catch (ConnectException e) {
                throw new SDKException("error getting kas servers", e);
            }
            tdfReaderConfig.kasAllowlist = new HashSet<>();

            for (var entry : response.getKeyAccessServersList()) {
                tdfReaderConfig.kasAllowlist.add(Config.getKasAddress(entry.getUri()));
            }
            tdfReaderConfig.kasAllowlist.add(Config.getKasAddress(platformUrl));
        }
        return loadTDF(tdf, tdfReaderConfig);
    }

    Reader loadTDF(SeekableByteChannel tdf, Config.TDFReaderConfig tdfReaderConfig) throws SDKException, IOException {

        TDFReader tdfReader = new TDFReader(tdf);
        String manifestJson = tdfReader.manifest();
        // use Manifest.readManifest in order to validate the Manifest input
        Manifest manifest = Manifest.readManifest(manifestJson);

        byte[] payloadKey = new byte[GCM_KEY_SIZE];
        String unencryptedMetadata = null;

        Set<String> knownSplits = new HashSet<>();
        Set<String> foundSplits = new HashSet<>();

        Map<Autoconfigure.KeySplitStep, Exception> skippedSplits = new HashMap<>();

        if (manifest.payload.isEncrypted) {
            for (Manifest.KeyAccess keyAccess : manifest.encryptionInformation.keyAccessObj) {
                String splitId = keyAccess.sid == null || keyAccess.sid.isEmpty() ? EMPTY_SPLIT_ID : keyAccess.sid;
                Autoconfigure.KeySplitStep ss = new Autoconfigure.KeySplitStep(keyAccess.url, splitId);
                byte[] unwrappedKey;
                if (foundSplits.contains(ss.splitID)) {
                    continue;
                }
                knownSplits.add(ss.splitID);
                try {
                    var realAddress = Config.getKasAddress(keyAccess.url);
                    if (tdfReaderConfig.ignoreKasAllowlist) {
                        logger.warn("Ignoring KasAllowlist for url {}", realAddress);
                    } else if (tdfReaderConfig.kasAllowlist == null || tdfReaderConfig.kasAllowlist.isEmpty()) {
                        logger.error(
                                "KasAllowlist: No KAS allowlist provided and no KeyAccessServerRegistry available, {} is not allowed",
                                realAddress);
                        throw new SDK.KasAllowlistException(
                                "No KAS allowlist provided and no KeyAccessServerRegistry available");
                    } else if (!tdfReaderConfig.kasAllowlist.contains(realAddress)) {
                        logger.error("KasAllowlist: kas url {} is not allowed", realAddress);
                        throw new SDK.KasAllowlistException("KasAllowlist: kas url " + realAddress + " is not allowed");
                    }
                    unwrappedKey = services.kas().unwrap(keyAccess, manifest.encryptionInformation.policy,
                            tdfReaderConfig.sessionKeyType);
                } catch (Exception e) {
                    skippedSplits.put(ss, e);
                    continue;
                }

                for (int index = 0; index < unwrappedKey.length; index++) {
                    payloadKey[index] ^= unwrappedKey[index];
                }
                foundSplits.add(ss.splitID);

                if (keyAccess.encryptedMetadata != null && !keyAccess.encryptedMetadata.isEmpty()) {
                    AesGcm aesGcm = new AesGcm(unwrappedKey);

                    String decodedMetadata = new String(Base64.getDecoder().decode(keyAccess.encryptedMetadata),
                            StandardCharsets.UTF_8);
                    EncryptedMetadata encryptedMetadata = gson.fromJson(decodedMetadata, EncryptedMetadata.class);

                    var encryptedData = new AesGcm.Encrypted(
                            decoder.decode(encryptedMetadata.ciphertext));

                    byte[] decrypted = aesGcm.decrypt(encryptedData);
                    // this is a little bit weird... the last unencrypted metadata we get from a KAS
                    // is the one
                    // that we return to the user. This is OK because we can't have different
                    // metadata per-KAS
                    unencryptedMetadata = new String(decrypted, StandardCharsets.UTF_8);
                }
            }

            if (knownSplits.size() > foundSplits.size()) {
                List<Exception> exceptionList = new ArrayList<>(skippedSplits.size() + 1);
                exceptionList.add(new Exception("splitKey.unable to reconstruct split key: " + skippedSplits));

                for (Map.Entry<Autoconfigure.KeySplitStep, Exception> entry : skippedSplits.entrySet()) {
                    exceptionList.add(entry.getValue());
                }

                StringBuilder combinedMessage = new StringBuilder();
                for (Exception e : exceptionList) {
                    combinedMessage.append(e.getMessage()).append("\n");
                }

                throw new SDK.SplitKeyException(combinedMessage.toString());
            }
        }

        // Validate root signature
        String rootAlgorithm = manifest.encryptionInformation.integrityInformation.rootSignature.algorithm;
        String rootSignature = manifest.encryptionInformation.integrityInformation.rootSignature.signature;

        ByteArrayOutputStream aggregateHash = new ByteArrayOutputStream();
        for (Manifest.Segment segment : manifest.encryptionInformation.integrityInformation.segments) {
            if (manifest.payload.isEncrypted) {
                byte[] decodedHash = Base64.getDecoder().decode(segment.hash);
                aggregateHash.write(decodedHash);
            } else {
                aggregateHash.write(segment.hash.getBytes());
            }
        }

        String rootSigValue;
        boolean isLegacyTdf = manifest.tdfVersion == null || manifest.tdfVersion.isEmpty();
        if (manifest.payload.isEncrypted) {
            var sigAlg = rootIntegrityAlgorithmFromManifest(rootAlgorithm);

            var sig = rootIntegrity(aggregateHash.toByteArray(), payloadKey, sigAlg);
            if (isLegacyTdf) {
                sig = Hex.encodeHexString(sig).getBytes();
            }
            rootSigValue = Base64.getEncoder().encodeToString(sig);
        } else {
            // KNOWN GAP, untouched by this change and tracked separately: this branch is a
            // bare SHA-256, so it authenticates nothing. `payload.isEncrypted` is itself
            // unauthenticated manifest data, so flipping it to false selects a keyless
            // verification path that anyone can satisfy -- and readPayload then emits the
            // segment bytes without decrypting them. Same downgrade shape as a GMAC root.
            // Left alone here because closing it means deciding whether unencrypted TDFs
            // are supported at all, which is a wider question than this fix.
            MessageDigest digest;
            try {
                digest = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("error getting instance of SHA-256 digest", e);
            }

            rootSigValue = Base64.getEncoder().encodeToString(digest.digest(aggregateHash.toString().getBytes()));
        }

        if (rootSignature.compareTo(rootSigValue) != 0) {
            throw new SDK.RootSignatureValidationException("root signature validation failed");
        }

        int segmentSize = manifest.encryptionInformation.integrityInformation.segmentSizeDefault;
        int encryptedSegSize = manifest.encryptionInformation.integrityInformation.encryptedSegmentSizeDefault;

        if (segmentSize != encryptedSegSize - (kGcmIvSize + AesGcm.GCM_TAG_LENGTH)) {
            throw new IllegalStateException(
                    "segment size mismatch. encrypted segment size differs from plaintext segment size. the TDF is invalid");
        }

        var aggregateHashByteArrayBytes = aggregateHash.toByteArray();
        // Validate assertions
        for (var assertion : manifest.assertions) {
            // Skip assertion verification if disabled
            if (tdfReaderConfig.disableAssertionVerification) {
                break;
            }

            // Set default to HS256
            var assertionKey = new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.HS256, payloadKey);
            Config.AssertionVerificationKeys assertionVerificationKeys = tdfReaderConfig.assertionVerificationKeys;
            if (!assertionVerificationKeys.isEmpty()) {
                var keyForAssertion = assertionVerificationKeys.getKey(assertion.id);
                if (keyForAssertion != null) {
                    assertionKey = keyForAssertion;
                }
            }

            Manifest.Assertion.HashValues hashValues;
            try {
                hashValues = assertion.verify(assertionKey);
            } catch (ParseException | JOSEException | java.security.cert.CertificateException e) {
                throw new SDKException("error validating assertion hash", e);
            }
            var hashOfAssertionAsHex = assertion.hash();

            if (!Objects.equals(hashOfAssertionAsHex, hashValues.getAssertionHash())) {
                throw new SDK.AssertionException("assertion hash mismatch", assertion.id);
            }

            byte[] hashOfAssertion;
            if (isLegacyTdf) {
                hashOfAssertion = hashOfAssertionAsHex.getBytes(StandardCharsets.UTF_8);
            } else {
                try {
                    hashOfAssertion = Hex.decodeHex(hashOfAssertionAsHex);
                } catch (DecoderException e) {
                    throw new SDKException("error decoding assertion hash", e);
                }
            }
            var signature = new byte[aggregateHashByteArrayBytes.length + hashOfAssertion.length];
            System.arraycopy(aggregateHashByteArrayBytes, 0, signature, 0, aggregateHashByteArrayBytes.length);
            System.arraycopy(hashOfAssertion, 0, signature, aggregateHashByteArrayBytes.length, hashOfAssertion.length);
            var encodeSignature = Base64.getEncoder().encodeToString(signature);

            if (!Objects.equals(encodeSignature, hashValues.getSignature())) {
                throw new SDK.AssertionException("failed integrity check on assertion signature", assertion.id);
            }
        }

        return new Reader(tdfReader, manifest, payloadKey, unencryptedMetadata);
    }
}
