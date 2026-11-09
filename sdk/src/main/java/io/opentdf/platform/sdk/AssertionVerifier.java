package io.opentdf.platform.sdk;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertUtils;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static io.opentdf.platform.sdk.AssertionFailureReason.ALGORITHM_MISMATCH;
import static io.opentdf.platform.sdk.AssertionFailureReason.BINDING_MISMATCH;
import static io.opentdf.platform.sdk.AssertionFailureReason.CONFIGURATION_ERROR;
import static io.opentdf.platform.sdk.AssertionFailureReason.INVALID_BINDING;
import static io.opentdf.platform.sdk.AssertionFailureReason.INVALID_EMBEDDED_KEY;
import static io.opentdf.platform.sdk.AssertionFailureReason.INVALID_ID;
import static io.opentdf.platform.sdk.AssertionFailureReason.SIGNATURE_INVALID;
import static io.opentdf.platform.sdk.AssertionFailureReason.SIGNER_NOT_PERMITTED;
import static io.opentdf.platform.sdk.AssertionFailureReason.UNSUPPORTED_ALGORITHM;
import static io.opentdf.platform.sdk.AssertionFailureReason.UNSUPPORTED_BINDING;

/**
 * Verifies assertion bindings as Section 8 of the ZTDF assertions specification lays out, in its
 * order, so the same input fails with the same reason in every SDK.
 * <p>
 * The verification key comes from the reader's configuration, or is the payload key when nothing
 * is configured, and is selected once per assertion. A key embedded in the JWS header, as
 * {@code jwk} or as the leaf of {@code x5c}, never replaces it and never chooses the algorithm:
 * it is accepted only when it is the same public key as the selected one. The signature is
 * always checked with the selected key and its configured algorithm. Nothing here reads the
 * network, and an {@code x5c} chain is not validated, so a pass says nothing about certificates.
 */
final class AssertionVerifier {

    private static final String ASSERTION_HASH = "assertionHash";
    private static final String ASSERTION_SIG = "assertionSig";
    private static final List<String> PRIVATE_JWK_MEMBERS = List.of("d", "p", "q", "dp", "dq", "qi", "oth");
    /** Untrusted values quoted in messages are cut to this many characters. */
    private static final int MAX_QUOTED = 64;

    private AssertionVerifier() {
    }

    /** The key one assertion is verified with, and the only key it can verify with. */
    static final class SelectedKey {
        final AssertionConfig.AssertionKeyAlg alg;
        private final JWSVerifier verifier;
        /** The public key's {@link #publicKeyIdentity identity}; null for HMAC keys. */
        private final String identity;

        private SelectedKey(AssertionConfig.AssertionKeyAlg alg, JWSVerifier verifier, String identity) {
            this.alg = alg;
            this.verifier = verifier;
            this.identity = identity;
        }

        static SelectedKey rsa(RSAPublicKey publicKey) {
            try {
                return new SelectedKey(AssertionConfig.AssertionKeyAlg.RS256, new RSASSAVerifier(publicKey),
                        publicKeyIdentity(publicKey));
            } catch (RuntimeException e) {
                throw new IllegalArgumentException("unusable RSA public key", e);
            }
        }

        static SelectedKey hmac(byte[] secret) {
            try {
                return new SelectedKey(AssertionConfig.AssertionKeyAlg.HS256, new MACVerifier(secret), null);
            } catch (JOSEException | RuntimeException e) {
                // MACVerifier refuses secrets shorter than 256 bits, as it always has
                throw new IllegalArgumentException("unusable HS256 secret: " + e.getMessage(), e);
            }
        }

        boolean isHmac() {
            return alg == AssertionConfig.AssertionKeyAlg.HS256;
        }

        private JWSAlgorithm jwsAlgorithm() {
            return isHmac() ? JWSAlgorithm.HS256 : JWSAlgorithm.RS256;
        }
    }

    /**
     * Verifies one assertion read from a manifest: Section 8, steps 3.1 to 3.9.
     *
     * @param keys          the reader's configured keys; null means none
     * @param payloadKey    used with HS256 only when no key is configured for the assertion
     * @param aggregateHash the decoded segment hashes, concatenated in manifest order
     * @param legacy        whether {@code assertionSig} carries the assertion hash as hex text
     * @throws SDK.AssertionFailureException on the first failed check
     */
    static void verify(Manifest.Assertion assertion, Config.AssertionVerificationKeys keys, byte[] payloadKey,
            byte[] aggregateHash, boolean legacy) {
        JsonObject json = assertion.received() != null ? assertion.received() : assertion.toJsonTree();
        String id = exactId(json);
        SelectedKey key = select(keys, id, payloadKey);
        verifyWithKey(json, id, key, aggregateHash, legacy);
    }

    /** Section 3.3: the exact {@code id}, which must be a nonempty JSON string. */
    static String exactId(JsonObject assertion) {
        JsonElement id = assertion.get("id");
        if (id == null || id.isJsonNull()) {
            throw new SDK.AssertionFailureException(null, INVALID_ID, "the assertion has no id");
        }
        if (!isString(id)) {
            throw new SDK.AssertionFailureException(null, INVALID_ID, "the assertion id is not a string");
        }
        if (id.getAsString().isEmpty()) {
            throw new SDK.AssertionFailureException(null, INVALID_ID, "the assertion id is empty");
        }
        return id.getAsString();
    }

    /**
     * Section 6.1: the key for the assertion with this exact id. A per-ID entry wins, then the
     * default key, then the payload key with HS256. An empty or invalid configured entry is a
     * {@code configuration-error}, never a reason to look further down the list.
     */
    static SelectedKey select(Config.AssertionVerificationKeys keys, String id, byte[] payloadKey) {
        if (keys != null && (keys.hasKeyFor(id) || keys.hasDefaultKey())) {
            String which = keys.hasKeyFor(id) ? "the verification key for this id" : "the default verification key";
            return configuredKey(keys.getKey(id), id, which);
        }
        try {
            return SelectedKey.hmac(payloadKey);
        } catch (IllegalArgumentException e) {
            throw new SDKException("the payload key cannot verify assertions", e);
        }
    }

    /**
     * A configured key as a {@link SelectedKey}: RS256 with an RSA public key (as
     * {@link RSAPublicKey} or an RSA {@link com.nimbusds.jose.jwk.JWK}), or HS256 with a {@code byte[]} secret.
     */
    static SelectedKey configuredKey(AssertionConfig.AssertionKey key, String id, String which) {
        if (key == null) {
            throw configurationError(id, which + " is empty");
        }
        if (key.alg == AssertionConfig.AssertionKeyAlg.RS256) {
            RSAPublicKey publicKey;
            if (key.key instanceof RSAPublicKey) {
                publicKey = (RSAPublicKey) key.key;
            } else if (key.key instanceof RSAKey) {
                try {
                    publicKey = ((RSAKey) key.key).toRSAPublicKey();
                } catch (JOSEException e) {
                    throw configurationError(id, which + " is not a usable RSA key");
                }
            } else {
                throw configurationError(id, which + " is RS256 but is not an RSA public key");
            }
            try {
                return SelectedKey.rsa(publicKey);
            } catch (IllegalArgumentException e) {
                throw configurationError(id, which + " is not a usable RSA key");
            }
        }
        if (key.alg == AssertionConfig.AssertionKeyAlg.HS256) {
            if (!(key.key instanceof byte[]) || ((byte[]) key.key).length == 0) {
                throw configurationError(id, which + " is HS256 but is not a nonempty byte[] secret");
            }
            if (isPemText((byte[]) key.key)) {
                // public-key bytes must never serve as an HMAC secret (spec Section 7)
                throw configurationError(id, which + " is HS256 but holds PEM text");
            }
            try {
                return SelectedKey.hmac((byte[]) key.key);
            } catch (IllegalArgumentException e) {
                throw configurationError(id, which + " is not a usable HS256 secret");
            }
        }
        throw configurationError(id, which + " has no supported algorithm");
    }

    /**
     * Section 8, steps 3.3 to 3.9, with the key already selected.
     *
     * @param assertion the assertion as parsed under Section 3, binding included
     * @param id        the assertion's exact id, for error reports; may be null
     */
    static void verifyWithKey(JsonObject assertion, String id, SelectedKey key, byte[] aggregateHash, boolean legacy) {
        Manifest.Assertion.HashValues claimed = verifyBinding(assertion, id, key);

        String assertionHash = AssertionJson.hash(assertion);
        if (!assertionHash.equals(claimed.getAssertionHash())) {
            throw new SDK.AssertionFailureException(id, BINDING_MISMATCH,
                    "the signed assertionHash does not match the assertion");
        }

        byte[] hashBytes;
        if (legacy) {
            hashBytes = assertionHash.getBytes(StandardCharsets.US_ASCII);
        } else {
            try {
                hashBytes = Hex.decodeHex(assertionHash);
            } catch (DecoderException e) {
                throw new IllegalStateException("assertion hash is not hex", e);
            }
        }
        byte[] expected = new byte[aggregateHash.length + hashBytes.length];
        System.arraycopy(aggregateHash, 0, expected, 0, aggregateHash.length);
        System.arraycopy(hashBytes, 0, expected, aggregateHash.length, hashBytes.length);
        if (!Base64.getEncoder().encodeToString(expected).equals(claimed.getSignature())) {
            // the other encoding is deliberately not tried
            throw new SDK.AssertionFailureException(id, BINDING_MISMATCH,
                    "failed integrity check on assertion signature: assertionSig does not match the segment hashes");
        }
    }

    /**
     * Section 8, steps 3.3 to 3.7: the binding form, the JWS and its header, any embedded keys,
     * the signature under the selected key, and the presence of the claims.
     *
     * @return the signed claims, still to be compared with the recomputed values
     */
    static Manifest.Assertion.HashValues verifyBinding(JsonObject assertion, String id, SelectedKey key) {
        Jws jws = Jws.parse(jwsBinding(assertion, id), id);

        // 3.4: the header
        if (jws.header.has("crit")) {
            throw invalidBinding(id, "the JWS header has a crit member");
        }
        JsonElement alg = jws.header.get("alg");
        if (alg == null || !isString(alg)) {
            throw new SDK.AssertionFailureException(id, UNSUPPORTED_ALGORITHM, "the JWS header has no alg");
        }
        String algName = alg.getAsString();
        if (!JWSAlgorithm.RS256.getName().equals(algName) && !JWSAlgorithm.HS256.getName().equals(algName)) {
            throw new SDK.AssertionFailureException(id, UNSUPPORTED_ALGORITHM,
                    "JWS alg " + quoted(algName) + " is not supported");
        }
        if (!algName.equals(key.jwsAlgorithm().getName())) {
            throw new SDK.AssertionFailureException(id, ALGORITHM_MISMATCH,
                    "JWS alg " + algName + " does not match the selected " + key.alg + " key");
        }

        // 3.5: embedded keys may only name the selected key
        checkEmbeddedKeys(jws.header, id, key);

        // 3.6: the signature, with the selected key and its algorithm only
        boolean verified = false;
        byte[] signature = strictBase64Url(jws.encodedSignature);
        if (signature != null) {
            try {
                verified = key.verifier.verify(new JWSHeader(key.jwsAlgorithm()), jws.signingInput(),
                        Base64URL.encode(signature));
            } catch (JOSEException e) {
                verified = false;
            }
        }
        if (!verified) {
            throw new SDK.AssertionFailureException(id, SIGNATURE_INVALID,
                    "unable to verify the assertion signature with the selected key");
        }

        // 3.7: the claims
        JsonElement assertionHash = jws.claims.get(ASSERTION_HASH);
        JsonElement assertionSig = jws.claims.get(ASSERTION_SIG);
        if (!isString(assertionHash) || !isString(assertionSig)) {
            throw new SDK.AssertionFailureException(id, BINDING_MISMATCH,
                    "the binding claims assertionHash and assertionSig must both be strings");
        }
        return new Manifest.Assertion.HashValues(assertionHash.getAsString(), assertionSig.getAsString());
    }

    /**
     * Section 5.1: the compact JWS of a JWS binding. The form is decided by which of
     * {@code signature} and {@code bdo} are present, before {@code method} is looked at.
     */
    static String jwsBinding(JsonObject assertion, String id) {
        JsonElement binding = assertion.get("binding");
        if (binding == null) {
            throw invalidBinding(id, "the assertion has no binding");
        }
        if (!binding.isJsonObject()) {
            throw invalidBinding(id, "the binding is not a JSON object");
        }
        JsonObject members = binding.getAsJsonObject();
        boolean hasSignature = members.has("signature");
        boolean hasBindingObject = members.has("bdo");
        if (hasSignature && hasBindingObject) {
            throw invalidBinding(id, "the binding has both a signature and a bdo");
        }
        if (!hasSignature && !hasBindingObject) {
            throw invalidBinding(id, "the binding has neither a signature nor a bdo");
        }
        if (hasBindingObject) {
            throw new SDK.AssertionFailureException(id, UNSUPPORTED_BINDING,
                    "STANAG 4778 binding objects are not supported");
        }
        JsonElement signature = members.get("signature");
        if (!isString(signature)) {
            throw invalidBinding(id, "the binding signature is not a string");
        }
        // a missing method means jws
        JsonElement method = members.get("method");
        if (method != null) {
            if (!isString(method)) {
                throw invalidBinding(id, "the binding method is not a string");
            }
            String name = method.getAsString();
            // current Java writers emitted the upper-case form
            if (!"jws".equals(name) && !"JWS".equals(name)) {
                throw new SDK.AssertionFailureException(id, UNSUPPORTED_BINDING,
                        "binding method " + quoted(name) + " is not supported");
            }
        }
        return signature.getAsString();
    }

    /**
     * A compact JWS, split, with its header and claims decoded and parsed as strict JSON. The
     * signature is decoded only when it is checked, so a malformed one is
     * {@code signature-invalid}.
     */
    private static final class Jws {
        final String encodedHeader;
        final String encodedPayload;
        final String encodedSignature;
        final JsonObject header;
        final JsonObject claims;

        private Jws(String[] parts, JsonObject header, JsonObject claims) {
            this.encodedHeader = parts[0];
            this.encodedPayload = parts[1];
            this.encodedSignature = parts[2];
            this.header = header;
            this.claims = claims;
        }

        static Jws parse(String compact, String id) {
            String[] parts = compact.split("\\.", -1);
            if (parts.length != 3) {
                throw invalidBinding(id, "the binding signature is not a compact JWS of three parts");
            }
            JsonObject header = decodeObject(parts[0], id, "header");
            JsonObject claims = decodeObject(parts[1], id, "payload");
            return new Jws(parts, header, claims);
        }

        byte[] signingInput() {
            return (encodedHeader + "." + encodedPayload).getBytes(StandardCharsets.US_ASCII);
        }

        private static JsonObject decodeObject(String part, String id, String what) {
            byte[] bytes = strictBase64Url(part);
            if (bytes == null) {
                throw invalidBinding(id, "the JWS " + what + " is not base64url");
            }
            JsonElement json;
            try {
                String text = StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(bytes))
                        .toString();
                json = AssertionJson.parseStrict(text);
            } catch (CharacterCodingException e) {
                throw invalidBinding(id, "the JWS " + what + " is not UTF-8");
            } catch (IOException | SDK.AssertionFailureException e) {
                throw invalidBinding(id, "the JWS " + what + " is not a strict JSON object");
            }
            if (!json.isJsonObject()) {
                throw invalidBinding(id, "the JWS " + what + " is not a JSON object");
            }
            return json.getAsJsonObject();
        }
    }

    /**
     * Unpadded base64url, as JWS (RFC 7515) requires, or null: the URL alphabet only, no
     * padding, and no non-zero bits after the last whole byte, so each byte string has exactly
     * one accepted encoding.
     */
    static byte[] strictBase64Url(String text) {
        if (text.length() % 4 == 1) {
            return null;
        }
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            boolean alphabet = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_';
            if (!alphabet) {
                return null;
            }
        }
        byte[] decoded = Base64.getUrlDecoder().decode(text);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(decoded).equals(text) ? decoded : null;
    }

    /**
     * Padded standard base64, as {@code x5c} (RFC 7515 Section 4.1.6) requires, or null: the
     * standard alphabet, correct padding, and no non-zero bits after the last whole byte.
     */
    private static byte[] strictBase64(String text) {
        if (text.length() % 4 != 0) {
            return null;
        }
        int padding = text.endsWith("==") ? 2 : text.endsWith("=") ? 1 : 0;
        for (int i = 0; i < text.length() - padding; i++) {
            char c = text.charAt(i);
            boolean alphabet = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '+' || c == '/';
            if (!alphabet) {
                return null;
            }
        }
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(text);
        } catch (IllegalArgumentException e) {
            return null;
        }
        return Base64.getEncoder().encodeToString(decoded).equals(text) ? decoded : null;
    }

    /** Section 6.2. */
    private static void checkEmbeddedKeys(JsonObject header, String id, SelectedKey key) {
        boolean hasJwk = header.has("jwk");
        boolean hasX5c = header.has("x5c");
        if (!hasJwk && !hasX5c) {
            return;
        }
        if (key.isHmac()) {
            throw new SDK.AssertionFailureException(id, INVALID_EMBEDDED_KEY,
                    "the JWS header embeds a key, but the selected key is an HMAC secret");
        }
        String fromJwk = hasJwk ? jwkIdentity(header.get("jwk"), id) : null;
        String fromX5c = hasX5c ? x5cLeafIdentity(header.get("x5c"), id) : null;
        if (fromJwk != null && fromX5c != null && !fromJwk.equals(fromX5c)) {
            throw new SDK.AssertionFailureException(id, INVALID_EMBEDDED_KEY,
                    "the jwk and x5c headers hold different keys");
        }
        String embedded = fromJwk != null ? fromJwk : fromX5c;
        if (!embedded.equals(key.identity)) {
            throw new SDK.AssertionFailureException(id, SIGNER_NOT_PERMITTED,
                    "the key embedded in the JWS header is not the selected verification key");
        }
    }

    /** The curves an EC jwk may name, with the byte length of each coordinate (RFC 7518 Section 6.2.1). */
    private static final Map<String, Curve> EC_CURVES = Map.of(
            Curve.P_256.getName(), Curve.P_256, Curve.P_384.getName(), Curve.P_384, Curve.P_521.getName(), Curve.P_521);

    /**
     * The OKP signature curves of RFC 8037, with the length of {@code x} and the DER prefix of the
     * key's SPKI. The key-agreement curves X25519 and X448 are not signing keys.
     */
    private enum OkpCurve {
        ED25519("Ed25519", 32, "302a300506032b6570032100"),
        ED448("Ed448", 57, "3043300506032b6571033a00");

        final String jwkName;
        final int length;
        final byte[] spkiPrefix;

        OkpCurve(String jwkName, int length, String spkiPrefix) {
            this.jwkName = jwkName;
            this.length = length;
            try {
                this.spkiPrefix = Hex.decodeHex(spkiPrefix);
            } catch (DecoderException e) {
                throw new IllegalStateException(e);
            }
        }

        static OkpCurve named(String name) {
            for (OkpCurve curve : values()) {
                if (curve.jwkName.equals(name)) {
                    return curve;
                }
            }
            return null;
        }
    }

    /**
     * The identity of an embedded public JWK, or {@code invalid-embedded-key} if it is not a
     * well-formed public key of its key type. Members are read from strict base64url. A
     * well-formed key of another type than the selected key simply has a different identity.
     */
    private static String jwkIdentity(JsonElement element, String id) {
        if (!element.isJsonObject()) {
            throw invalidEmbeddedKey(id, "the jwk header is not a JSON object");
        }
        JsonObject members = element.getAsJsonObject();
        JsonElement kty = members.get("kty");
        if (!isString(kty)) {
            throw invalidEmbeddedKey(id, "the jwk header has no kty");
        }
        if ("oct".equals(kty.getAsString())) {
            throw invalidEmbeddedKey(id, "the jwk header holds a symmetric key");
        }
        for (String member : PRIVATE_JWK_MEMBERS) {
            if (members.has(member)) {
                throw invalidEmbeddedKey(id, "the jwk header holds private key material");
            }
        }
        switch (kty.getAsString()) {
            case "RSA":
                return rsaIdentity(jwkUnsigned(members, "n", id), jwkUnsigned(members, "e", id));
            case "EC": {
                JsonElement crv = members.get("crv");
                Curve curve = isString(crv) ? EC_CURVES.get(crv.getAsString()) : null;
                if (curve == null) {
                    throw invalidEmbeddedKey(id, "the jwk header names no supported EC curve");
                }
                byte[] x = jwkBytes(members, "x", id);
                byte[] y = jwkBytes(members, "y", id);
                int size = (curve.toECParameterSpec().getCurve().getField().getFieldSize() + 7) / 8;
                if (x.length != size || y.length != size) {
                    throw invalidEmbeddedKey(id, "the jwk header has EC coordinates of the wrong length");
                }
                BigInteger affineX = new BigInteger(1, x);
                BigInteger affineY = new BigInteger(1, y);
                if (!isOnCurve(curve, affineX, affineY)) {
                    throw invalidEmbeddedKey(id, "the jwk header has an EC point that is not on its curve");
                }
                return ecIdentity(curve, affineX, affineY);
            }
            case "OKP": {
                JsonElement crv = members.get("crv");
                OkpCurve curve = isString(crv) ? OkpCurve.named(crv.getAsString()) : null;
                if (curve == null) {
                    throw invalidEmbeddedKey(id, "the jwk header names no OKP signature curve");
                }
                byte[] x = jwkBytes(members, "x", id);
                if (x.length != curve.length) {
                    throw invalidEmbeddedKey(id, "the jwk header has an OKP key of the wrong length");
                }
                return okpIdentity(curve, x);
            }
            default:
                throw invalidEmbeddedKey(id, "the jwk header has an unsupported key type");
        }
    }

    /** An RSA jwk integer, in the minimum number of octets RFC 7518 Section 6.3.1 requires. */
    private static BigInteger jwkUnsigned(JsonObject jwk, String member, String id) {
        byte[] bytes = jwkBytes(jwk, member, id);
        if (bytes[0] == 0) {
            throw invalidEmbeddedKey(id, "the jwk member " + member + " has a leading zero octet");
        }
        return new BigInteger(1, bytes);
    }

    private static byte[] jwkBytes(JsonObject jwk, String member, String id) {
        JsonElement value = jwk.get(member);
        byte[] bytes = isString(value) ? strictBase64Url(value.getAsString()) : null;
        if (bytes == null || bytes.length == 0) {
            throw invalidEmbeddedKey(id, "the jwk member " + member + " is not base64url");
        }
        return bytes;
    }

    private static boolean isOnCurve(Curve curve, BigInteger x, BigInteger y) {
        ECParameterSpec spec = curve.toECParameterSpec();
        BigInteger p = ((ECFieldFp) spec.getCurve().getField()).getP();
        if (x.compareTo(p) >= 0 || y.compareTo(p) >= 0) {
            return false;
        }
        BigInteger right = x.pow(3).add(spec.getCurve().getA().multiply(x)).add(spec.getCurve().getB());
        return y.pow(2).subtract(right).mod(p).signum() == 0;
    }

    /**
     * The identity of the public key in the leaf of an embedded {@code x5c}, or
     * {@code invalid-embedded-key}. Certificates after the leaf must decode as base64 and are
     * otherwise ignored: never parsed, no chain is built or validated, and nothing is said
     * about validity.
     */
    private static String x5cLeafIdentity(JsonElement element, String id) {
        if (!element.isJsonArray() || element.getAsJsonArray().size() == 0) {
            throw invalidEmbeddedKey(id, "the x5c header is not a nonempty array");
        }
        JsonArray chain = element.getAsJsonArray();
        byte[] leaf = null;
        for (JsonElement certificate : chain) {
            byte[] der = isString(certificate) ? strictBase64(certificate.getAsString()) : null;
            if (der == null || der.length == 0) {
                throw invalidEmbeddedKey(id, "the x5c header holds a value that is not padded standard base64");
            }
            if (leaf == null) {
                leaf = der;
            }
        }
        X509Certificate certificate;
        try {
            certificate = X509CertUtils.parseWithException(leaf);
        } catch (CertificateException | RuntimeException e) {
            throw invalidEmbeddedKey(id, "the x5c leaf is not a DER certificate");
        }
        // the parser also takes PEM text and ignores bytes after the certificate; accept only
        // exactly one DER certificate
        try {
            if (certificate == null || !Arrays.equals(certificate.getEncoded(), leaf)) {
                throw invalidEmbeddedKey(id, "the x5c leaf is not exactly one DER certificate");
            }
        } catch (CertificateException e) {
            throw invalidEmbeddedKey(id, "the x5c leaf is not a DER certificate");
        }
        return publicKeyIdentity(certificate.getPublicKey());
    }

    /**
     * Two keys are the same key exactly when their identities are equal. This is equivalent to
     * comparing RFC 7638 SHA-256 thumbprints over the required public members: an embedded jwk
     * must already use the canonical encoding (minimal RSA integers, full-length EC
     * coordinates, strict base64url), so its members encode exactly these values.
     */
    static String publicKeyIdentity(PublicKey publicKey) {
        if (publicKey instanceof RSAPublicKey) {
            RSAPublicKey rsa = (RSAPublicKey) publicKey;
            return rsaIdentity(rsa.getModulus(), rsa.getPublicExponent());
        }
        if (publicKey instanceof ECPublicKey) {
            ECPublicKey ec = (ECPublicKey) publicKey;
            Curve curve = Curve.forECParameterSpec(ec.getParams());
            if (curve != null && EC_CURVES.containsKey(curve.getName())) {
                return ecIdentity(curve, ec.getW().getAffineX(), ec.getW().getAffineY());
            }
        }
        byte[] spki = publicKey.getEncoded();
        for (OkpCurve curve : OkpCurve.values()) {
            if (spki.length == curve.spkiPrefix.length + curve.length
                    && Arrays.equals(spki, 0, curve.spkiPrefix.length, curve.spkiPrefix, 0, curve.spkiPrefix.length)) {
                return okpIdentity(curve, Arrays.copyOfRange(spki, curve.spkiPrefix.length, spki.length));
            }
        }
        return "spki:" + Base64.getEncoder().encodeToString(spki);
    }

    private static String rsaIdentity(BigInteger modulus, BigInteger exponent) {
        return "rsa:" + modulus.toString(16) + ":" + exponent.toString(16);
    }

    private static String ecIdentity(Curve curve, BigInteger x, BigInteger y) {
        return "ec:" + curve.getName() + ":" + x.toString(16) + ":" + y.toString(16);
    }

    private static String okpIdentity(OkpCurve curve, byte[] x) {
        return "okp:" + curve.jwkName + ":" + Hex.encodeHexString(x);
    }

    private static final byte[] PEM_MARKER = "-----BEGIN".getBytes(StandardCharsets.US_ASCII);

    /** True if the secret contains a PEM armour line, as public-key text does. */
    static boolean isPemText(byte[] secret) {
        outer:
        for (int i = 0; i + PEM_MARKER.length <= secret.length; i++) {
            for (int j = 0; j < PEM_MARKER.length; j++) {
                if (secret[i + j] != PEM_MARKER[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    private static boolean isString(JsonElement element) {
        return element != null && element.isJsonPrimitive() && element.getAsJsonPrimitive().isString();
    }

    private static String quoted(String untrusted) {
        return "\"" + (untrusted.length() > MAX_QUOTED ? untrusted.substring(0, MAX_QUOTED) + "..." : untrusted) + "\"";
    }

    private static SDK.AssertionFailureException invalidBinding(String id, String detail) {
        return new SDK.AssertionFailureException(id, INVALID_BINDING, detail);
    }

    private static SDK.AssertionFailureException invalidEmbeddedKey(String id, String detail) {
        return new SDK.AssertionFailureException(id, INVALID_EMBEDDED_KEY, detail);
    }

    private static SDK.AssertionFailureException configurationError(String id, String detail) {
        return new SDK.AssertionFailureException(id, CONFIGURATION_ERROR, detail);
    }
}
