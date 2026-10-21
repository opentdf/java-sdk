package io.opentdf.platform.sdk;

import com.google.gson.ExclusionStrategy;
import com.google.gson.FieldAttributes;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import com.google.gson.TypeAdapter;
import com.google.gson.TypeAdapterFactory;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.opentdf.platform.sdk.SDK.AssertionException;
import org.apache.commons.codec.binary.Hex;
import org.erdtman.jcs.JsonCanonicalizer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The Manifest class represents a detailed structure encapsulating various
 * aspects
 * of data integrity, encryption, payload, and assertions within a certain
 * context.
 */
public class Manifest {

    private static final String kAssertionHash = "assertionHash";
    private static final String kAssertionSignature = "assertionSig";

    private static final Gson gson = new GsonBuilder()
            .addSerializationExclusionStrategy(new DeserializeOnlyExclusionStrategy())
            .registerTypeAdapter(AssertionConfig.Statement.class, new AssertionValueAdapter())
            .registerTypeAdapterFactory(new IntegrityInformationAdapterFactory())
            .registerTypeAdapterFactory(new SpecVersionAdapterFactory())
            .create();

    /**
     * The TDF spec version the manifest records. Written as {@code schemaVersion} only; on read
     * it may also come from the non-aligned {@code tdf_spec_version} name, see
     * {@link SpecVersionAdapterFactory}.
     * <p>
     * The reader uses it to choose how the integrity digests are encoded: hex when no version is
     * recorded (pre-4.3.0), raw bytes otherwise.
     */
    @SerializedName(value = "schemaVersion")
    String tdfVersion;

    @DeserializeOnly
    @SerializedName("tdf_spec_version")
    JsonElement nonAlignedSpecVersion;

    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.FIELD)
    private @interface DeserializeOnly {
    }

    private static final class DeserializeOnlyExclusionStrategy implements ExclusionStrategy {
        @Override
        public boolean shouldSkipField(FieldAttributes field) {
            return field.getAnnotation(DeserializeOnly.class) != null;
        }

        @Override
        public boolean shouldSkipClass(Class<?> type) {
            return false;
        }
    }

    public static String toJson(Manifest manifest) {
        return gson.toJson(manifest);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Manifest manifest = (Manifest) o;
        return Objects.equals(tdfVersion, manifest.tdfVersion) && Objects.equals(encryptionInformation, manifest.encryptionInformation) && Objects.equals(payload, manifest.payload) && Objects.equals(assertions, manifest.assertions);
    }

    @Override
    public int hashCode() {
        return Objects.hash(tdfVersion, encryptionInformation, payload, assertions);
    }

    private static class PolicyBindingSerializer implements JsonDeserializer<Object>, JsonSerializer<Object> {
        @Override
        public Object deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context)
                throws JsonParseException {
            if (json.isJsonObject()) {
                return context.deserialize(json, Manifest.PolicyBinding.class);
            } else if (json.isJsonPrimitive() && json.getAsJsonPrimitive().isString()) {
                return json.getAsString();
            } else {
                throw new JsonParseException("Unexpected type for policyBinding");
            }
        }

        @Override
        public JsonElement serialize(Object src, Type typeOfSrc, JsonSerializationContext context) {
            return context.serialize(src, typeOfSrc);
        }
    }

    static public class Segment {
        public String hash;
        /**
         * The plaintext length of this segment. Optional when parsing: a producer that leaves the
         * key out means {@link IntegrityInformation#segmentSizeDefault}, which is filled in during
         * deserialization. Always written on serialization, so a manifest read and re-emitted by
         * this SDK carries the value explicitly.
         */
        public long segmentSize;
        /**
         * The on-the-wire length of this segment. Optional when parsing the same way
         * {@link #segmentSize} is, defaulting to
         * {@link IntegrityInformation#encryptedSegmentSizeDefault}.
         */
        public long encryptedSegmentSize;
        @SuppressWarnings("java:S2065") // Gson uses transient to keep parser state out of manifest JSON.
        private transient boolean segmentSizePresent = true;
        @SuppressWarnings("java:S2065") // Gson uses transient to keep parser state out of manifest JSON.
        private transient boolean encryptedSegmentSizePresent = true;

        @Override
        public boolean equals(Object o) {
            if (this == o)
                return true;
            if (o == null || getClass() != o.getClass())
                return false;
            Segment segment = (Segment) o;
            return segmentSize == segment.segmentSize && encryptedSegmentSize == segment.encryptedSegmentSize
                    && Objects.equals(hash, segment.hash);
        }

        @Override
        public int hashCode() {
            return Objects.hash(hash, segmentSize, encryptedSegmentSize);
        }
    }

    /**
     * A compact, append-only {@link Segment} list.
     * <p>
     * A plain {@code ArrayList<Segment>} costs roughly 176 bytes per segment, which
     * is several gigabytes for a multi-terabyte payload. Every segment of a TDF but
     * the last has the same sizes, and every segment hash is the same fixed length,
     * so all this stores is the hash characters packed into fixed-stride chunks
     * plus the two size pairs — about 24 bytes per segment, with no array-growth
     * copies and no {@code Integer.MAX_VALUE} ceiling on the backing store.
     * <p>
     * {@link #append} refuses anything that does not fit those assumptions (a
     * manifest from another writer may not honor them); callers fall back to an
     * {@code ArrayList}.
     * <p>
     * ponytail: the remaining ceiling is {@link #aggregate}, which materializes one
     * byte array of {@code count * hashLength} — about 134M segments (256 TiB at
     * 2 MiB segments), or ~100M if the TDF carries assertions, whose signature is
     * base64 of that array. Going past that needs a streaming Mac and streaming
     * base64, and a wire-format change for assertions.
     */
    @SuppressWarnings("java:S2160") // AbstractList equality is the intended list-value equality.
    static final class Segments extends AbstractList<Segment> {
        private static final int SEGMENTS_PER_CHUNK = 4096;
        /**
         * A chunk is {@code stride * SEGMENTS_PER_CHUNK} bytes, so an absurd hash in an
         * untrusted manifest would size the very first allocation. The longest hash any
         * writer produces is 128 characters (hex-encoded HS256); anything past this is
         * left to the {@code ArrayList} fallback, which only ever costs what the input
         * itself costs.
         */
        private static final int MAX_HASH_LENGTH = 1024;

        private final List<byte[]> chunks = new ArrayList<>();
        private final Map<Integer, Segment> materializedSegments = new HashMap<>();
        private List<Segment> mutableSegments;
        private int count;
        /** Length of every hash, in characters; established by the first append. */
        private int stride;
        /** Trailing '=' in every hash, so decoded hashes are also fixed length. */
        private int padding;
        private long defaultSegmentSize;
        private long defaultEncryptedSegmentSize;
        private boolean defaultSegmentSizePresent;
        private boolean defaultEncryptedSegmentSizePresent;
        private long lastSegmentSize;
        private long lastEncryptedSegmentSize;
        private boolean lastSegmentSizePresent;
        private boolean lastEncryptedSegmentSizePresent;

        /**
         * @return false if this segment cannot be represented compactly, in which
         *         case the segment was not appended and the caller must fall back
         */
        boolean append(String hash, long segmentSize, long encryptedSegmentSize) {
            return append(hash, segmentSize, encryptedSegmentSize, true, true);
        }

        private boolean append(Segment segment) {
            return segment != null && append(segment.hash, segment.segmentSize, segment.encryptedSegmentSize,
                    segment.segmentSizePresent, segment.encryptedSegmentSizePresent);
        }

        private boolean append(String hash, long segmentSize, long encryptedSegmentSize,
                boolean segmentSizePresent, boolean encryptedSegmentSizePresent) {
            if (hash == null) {
                return false;
            }
            if (count == 0) {
                if (hash.isEmpty() || hash.length() > MAX_HASH_LENGTH) {
                    return false;
                }
                stride = hash.length();
                padding = trailingPadding(hash);
                defaultSegmentSize = segmentSize;
                defaultEncryptedSegmentSize = encryptedSegmentSize;
                defaultSegmentSizePresent = segmentSizePresent;
                defaultEncryptedSegmentSizePresent = encryptedSegmentSizePresent;
            } else if (hash.length() != stride
                    || trailingPadding(hash) != padding
                    // the previously appended segment is no longer the last one, so it
                    // has to match the defaults from here on
                    || !sameValue(lastSegmentSize, lastSegmentSizePresent,
                            defaultSegmentSize, defaultSegmentSizePresent)
                    || !sameValue(lastEncryptedSegmentSize, lastEncryptedSegmentSizePresent,
                            defaultEncryptedSegmentSize, defaultEncryptedSegmentSizePresent)) {
                return false;
            }

            if (count % SEGMENTS_PER_CHUNK == 0) {
                chunks.add(new byte[stride * SEGMENTS_PER_CHUNK]);
            }
            byte[] chunk = chunks.get(count / SEGMENTS_PER_CHUNK);
            int offset = (count % SEGMENTS_PER_CHUNK) * stride;
            for (int i = 0; i < stride; i++) {
                char c = hash.charAt(i);
                if (c > 0x7f) { // non-ASCII would not survive the byte-per-character packing
                    return false;
                }
                chunk[offset + i] = (byte) c;
            }

            lastSegmentSize = segmentSize;
            lastEncryptedSegmentSize = encryptedSegmentSize;
            lastSegmentSizePresent = segmentSizePresent;
            lastEncryptedSegmentSizePresent = encryptedSegmentSizePresent;
            count++;
            return true;
        }

        private static boolean sameValue(long left, boolean leftPresent, long right, boolean rightPresent) {
            return leftPresent == rightPresent && (!leftPresent || left == right);
        }

        private void applyDefaults(long segmentSize, long encryptedSegmentSize) {
            if (!defaultSegmentSizePresent) {
                defaultSegmentSize = segmentSize;
                defaultSegmentSizePresent = true;
            }
            if (!defaultEncryptedSegmentSizePresent) {
                defaultEncryptedSegmentSize = encryptedSegmentSize;
                defaultEncryptedSegmentSizePresent = true;
            }
            if (!lastSegmentSizePresent) {
                lastSegmentSize = segmentSize;
                lastSegmentSizePresent = true;
            }
            if (!lastEncryptedSegmentSizePresent) {
                lastEncryptedSegmentSize = encryptedSegmentSize;
                lastEncryptedSegmentSizePresent = true;
            }
        }

        private static int trailingPadding(String hash) {
            int padding = 0;
            while (padding < hash.length() && hash.charAt(hash.length() - 1 - padding) == '=') {
                padding++;
            }
            return padding;
        }

        /**
         * Every segment hash concatenated, base64-decoded if {@code decodeBase64}
         * and taken as raw ASCII otherwise. This is the aggregate hash that the root
         * signature and the assertion signatures are computed over.
         */
        byte[] aggregate(boolean decodeBase64) {
            if (size() == 0) {
                return new byte[0];
            }
            if (mutableSegments != null || !materializedSegments.isEmpty()) {
                return aggregateMaterialized(decodeBase64);
            }
            byte[] scratch = new byte[stride];
            if (!decodeBase64) {
                byte[] aggregate = new byte[Math.multiplyExact(count, stride)];
                for (int i = 0; i < count; i++) {
                    copyHash(i, aggregate, i * stride);
                }
                return aggregate;
            }

            copyHash(0, scratch, 0);
            int decodedStride = Base64.getDecoder().decode(scratch).length;
            byte[] aggregate = new byte[Math.multiplyExact(count, decodedStride)];
            byte[] decoded = new byte[decodedStride];
            for (int i = 0; i < count; i++) {
                copyHash(i, scratch, 0);
                Base64.getDecoder().decode(scratch, decoded);
                System.arraycopy(decoded, 0, aggregate, i * decodedStride, decodedStride);
            }
            return aggregate;
        }

        private byte[] aggregateMaterialized(boolean decodeBase64) {
            ByteArrayOutputStream aggregate = new ByteArrayOutputStream();
            for (int i = 0; i < size(); i++) {
                String hash = getForRead(i).hash;
                byte[] bytes = decodeBase64
                        ? Base64.getDecoder().decode(hash)
                        : hash.getBytes(StandardCharsets.US_ASCII);
                aggregate.write(bytes, 0, bytes.length);
            }
            return aggregate.toByteArray();
        }

        private void copyHash(int index, byte[] destination, int destinationOffset) {
            byte[] chunk = chunks.get(index / SEGMENTS_PER_CHUNK);
            System.arraycopy(chunk, (index % SEGMENTS_PER_CHUNK) * stride, destination, destinationOffset, stride);
        }

        @Override
        public Segment get(int index) {
            if (mutableSegments != null) {
                return mutableSegments.get(index);
            }
            Objects.checkIndex(index, count);
            return materializedSegments.computeIfAbsent(index, this::unpack);
        }

        Segment getForRead(int index) {
            if (mutableSegments != null) {
                return mutableSegments.get(index);
            }
            Objects.checkIndex(index, count);
            Segment materialized = materializedSegments.get(index);
            return materialized == null ? unpack(index) : materialized;
        }

        private Segment unpack(int index) {
            byte[] chunk = chunks.get(index / SEGMENTS_PER_CHUNK);
            Segment segment = new Segment();
            segment.hash = new String(chunk, (index % SEGMENTS_PER_CHUNK) * stride, stride, StandardCharsets.US_ASCII);
            boolean last = index == count - 1;
            segment.segmentSize = last ? lastSegmentSize : defaultSegmentSize;
            segment.encryptedSegmentSize = last ? lastEncryptedSegmentSize : defaultEncryptedSegmentSize;
            segment.segmentSizePresent = last ? lastSegmentSizePresent : defaultSegmentSizePresent;
            segment.encryptedSegmentSizePresent = last
                    ? lastEncryptedSegmentSizePresent : defaultEncryptedSegmentSizePresent;
            return segment;
        }

        private void materialize() {
            if (mutableSegments != null) {
                return;
            }
            List<Segment> copy = new ArrayList<>(count);
            for (int i = 0; i < count; i++) {
                copy.add(getForRead(i));
            }
            mutableSegments = copy;
            materializedSegments.clear();
            chunks.clear();
        }

        @Override
        public Segment set(int index, Segment element) {
            materialize();
            return mutableSegments.set(index, element);
        }

        @Override
        public void add(int index, Segment element) {
            materialize();
            mutableSegments.add(index, element);
            count = mutableSegments.size();
            modCount++;
        }

        @Override
        public Segment remove(int index) {
            materialize();
            Segment removed = mutableSegments.remove(index);
            count = mutableSegments.size();
            modCount++;
            return removed;
        }

        @Override
        public int size() {
            return mutableSegments == null ? count : mutableSegments.size();
        }
    }

    static Segment segmentAt(List<Segment> segments, int index) {
        return segments instanceof Segments
                ? ((Segments) segments).getForRead(index)
                : segments.get(index);
    }

    /**
     * Reads {@code segments} into a {@link Segments} when the manifest allows it,
     * and into a plain {@code ArrayList} when it does not. Writing delegates to the
     * reflective {@link Segment} adapter, so the JSON is unchanged either way.
     */
    static final class SegmentsAdapterFactory implements TypeAdapterFactory {
        @Override
        @SuppressWarnings("unchecked")
        public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
            TypeAdapter<Segment> element = gson.getAdapter(Segment.class);
            TypeAdapter<JsonElement> jsonElement = gson.getAdapter(JsonElement.class);
            return (TypeAdapter<T>) new SegmentsTypeAdapter(element, jsonElement);
        }

        private static boolean hasValue(JsonObject object, String memberName) {
            JsonElement member = object.get(memberName);
            return member != null && !member.isJsonNull();
        }
    }

    private static final class SegmentsTypeAdapter extends TypeAdapter<List<Segment>> {
        private final TypeAdapter<Segment> elementAdapter;
        private final TypeAdapter<JsonElement> jsonElementAdapter;

        private SegmentsTypeAdapter(TypeAdapter<Segment> elementAdapter,
                TypeAdapter<JsonElement> jsonElementAdapter) {
            this.elementAdapter = elementAdapter;
            this.jsonElementAdapter = jsonElementAdapter;
        }

        @Override
        public void write(JsonWriter out, List<Segment> value) throws IOException {
            if (value == null) {
                out.nullValue();
                return;
            }
            out.beginArray();
            for (int i = 0; i < value.size(); i++) {
                elementAdapter.write(out, segmentAt(value, i));
            }
            out.endArray();
        }

        @Override
        @SuppressWarnings("java:S1168") // Preserve JSON null so manifest validation rejects it.
        public List<Segment> read(JsonReader in) throws IOException {
            if (in.peek() == JsonToken.NULL) {
                in.nextNull();
                return null;
            }
            in.beginArray();
            Segments compact = new Segments();
            List<Segment> fallback = null;
            while (in.hasNext()) {
                Segment segment = readSegment(in);
                if (fallback != null) {
                    fallback.add(segment);
                } else if (!compact.append(segment)) {
                    fallback = new ArrayList<>(compact);
                    fallback.add(segment);
                }
            }
            in.endArray();
            return fallback == null ? compact : fallback;
        }

        private Segment readSegment(JsonReader in) throws IOException {
            JsonElement rawSegment = jsonElementAdapter.read(in);
            Segment segment = elementAdapter.fromJsonTree(rawSegment);
            if (segment != null && rawSegment.isJsonObject()) {
                JsonObject object = rawSegment.getAsJsonObject();
                segment.segmentSizePresent = SegmentsAdapterFactory.hasValue(object, "segmentSize");
                segment.encryptedSegmentSizePresent = SegmentsAdapterFactory.hasValue(
                        object, "encryptedSegmentSize");
            }
            return segment;
        }
    }

    static public class RootSignature {
        @SerializedName(value = "alg")
        public String algorithm;
        @SerializedName(value = "sig")
        public String signature;

        @Override
        public boolean equals(Object o) {
            if (this == o)
                return true;
            if (o == null || getClass() != o.getClass())
                return false;
            RootSignature that = (RootSignature) o;
            return Objects.equals(algorithm, that.algorithm) && Objects.equals(signature, that.signature);
        }

        @Override
        public int hashCode() {
            return Objects.hash(algorithm, signature);
        }
    }

    static public class IntegrityInformation {
        public RootSignature rootSignature;
        public String segmentHashAlg;
        public int segmentSizeDefault;
        public int encryptedSegmentSizeDefault;
        @JsonAdapter(SegmentsAdapterFactory.class)
        public List<Segment> segments;

        @Override
        public boolean equals(Object o) {
            if (this == o)
                return true;
            if (o == null || getClass() != o.getClass())
                return false;
            IntegrityInformation that = (IntegrityInformation) o;
            return segmentSizeDefault == that.segmentSizeDefault
                    && encryptedSegmentSizeDefault == that.encryptedSegmentSizeDefault
                    && Objects.equals(rootSignature, that.rootSignature)
                    && Objects.equals(segmentHashAlg, that.segmentHashAlg) && Objects.equals(segments, that.segments);
        }

        @Override
        public int hashCode() {
            return Objects.hash(rootSignature, segmentHashAlg, segmentSizeDefault, encryptedSegmentSizeDefault,
                    segments);
        }
    }

    /**
     * Applies {@code segmentSizeDefault} / {@code encryptedSegmentSizeDefault} to any segment
     * that left the corresponding per-segment key out of its JSON.
     * <p>
     * The per-segment values are optional overrides. As of 2026-09,
     * <a href="https://github.com/opentdf/spec/blob/main/schema/OpenTDF/json-schema/schema.json">the
     * TDF schema</a> lists {@code segmentSizeDefault} and {@code encryptedSegmentSizeDefault} in
     * {@code integrityInformation}'s {@code required} array but puts no {@code required} array on
     * {@code segments/items}, and web-sdk omits a per-segment size whenever it equals the default
     * -- which is every full segment of a payload larger than one segment. Gson leaves an absent
     * key at {@code 0}, so before this the reader allocated a zero length buffer for those
     * segments and failed inside the integrity check.
     * <p>
     * This runs as a post-deserialization fixup rather than by boxing the fields to {@code Long},
     * which keeps {@link Segment#segmentSize} a primitive for callers and keeps the value/absence
     * distinction out of the public API.
     * <p>
     * Two edge cases worth knowing: an explicit {@code null} is treated as absent and gets the
     * default, while an explicit {@code 0} is a value and is left alone for the reader to reject.
     * And if the manifest omits a <em>default</em> too then there is nothing to fall back to, so
     * the segments keep their {@code 0}; {@code TDF.loadTDF} rejects that manifest when it checks
     * the two defaults against each other.
     */
    private static class IntegrityInformationAdapterFactory implements TypeAdapterFactory {
        @Override
        public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
            if (!IntegrityInformation.class.equals(type.getRawType())) {
                return null;
            }
            final TypeAdapter<T> delegate = gson.getDelegateAdapter(this, type);
            return new TypeAdapter<T>() {
                @Override
                public void write(JsonWriter out, T value) throws IOException {
                    delegate.write(out, value);
                }

                @Override
                public T read(JsonReader in) throws IOException {
                    T value = delegate.read(in);
                    if (value instanceof IntegrityInformation) {
                        applySegmentSizeDefaults((IntegrityInformation) value);
                    }
                    return value;
                }
            };
        }

        private static void applySegmentSizeDefaults(IntegrityInformation integrityInformation) {
            List<Segment> segments = integrityInformation.segments;
            if (segments == null) {
                // no segments to default; readManifest rejects this with its own message
                return;
            }
            if (segments instanceof Segments) {
                ((Segments) segments).applyDefaults(integrityInformation.segmentSizeDefault,
                        integrityInformation.encryptedSegmentSizeDefault);
                return;
            }
            for (int i = 0; i < segments.size(); i++) {
                Segment segment = segments.get(i);
                if (segment == null) {
                    // a null entry in the array; readManifest rejects it with its own message
                    continue;
                }
                if (!segment.segmentSizePresent) {
                    segment.segmentSize = integrityInformation.segmentSizeDefault;
                }
                if (!segment.encryptedSegmentSizePresent) {
                    segment.encryptedSegmentSize = integrityInformation.encryptedSegmentSizeDefault;
                }
            }
        }
    }

    /**
     * Reads {@code tdf_spec_version}, a non-aligned name for the spec-version field, when the
     * canonical {@code schemaVersion} is absent, so that files written with that name stay
     * readable.
     * <p>
     * {@code schemaVersion} is the canonical name. {@code tdf_spec_version} is not a former
     * spelling that was renamed -- it entered some specification drafts and some older OpenTDF
     * documentation in error, and writers built from those drafts emitted it. We read it so
     * those files stay usable; we never write it.
     * <p>
     * Precedence is {@code schemaVersion}, then {@code tdf_spec_version} at the root, then
     * {@code tdf_spec_version} under {@code payload}. Nothing is written back under the
     * non-aligned name -- serializing a manifest always emits {@code schemaVersion} only, so a
     * round trip normalizes the name rather than propagating it.
     * <p>
     * Both placements are probed because both occur in archival files. The root is where the
     * spec's own manifest.md has always documented the field, and where web-sdk both wrote it
     * and still reads it. Under {@code payload} is where revisions of the JSON schema declared it
     * in error, which led at least one writer to emit the key there with a {@code null} value.
     * <p>
     * Only a non-empty JSON string counts. Any other value -- {@code null}, a number, an object
     * -- is skipped rather than failing the decode: reporting malformed manifests is schema
     * validation's job, not the decoder's.
     * <p>
     * Gson's {@code @SerializedName(alternate = ...)} cannot do this: it cannot reach into
     * {@code payload}, and when both names are present it keeps whichever comes last in the
     * document instead of preferring {@code schemaVersion}.
     */
    private static class SpecVersionAdapterFactory implements TypeAdapterFactory {
        @Override
        public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
            if (!Manifest.class.equals(type.getRawType())) {
                return null;
            }
            final TypeAdapter<T> delegate = gson.getDelegateAdapter(this, type);
            return new TypeAdapter<T>() {
                @Override
                public void write(JsonWriter out, T value) throws IOException {
                    delegate.write(out, value);
                }

                @Override
                public T read(JsonReader in) throws IOException {
                    T value = delegate.read(in);
                    if (value instanceof Manifest) {
                        Manifest manifest = (Manifest) value;
                        if (manifest.tdfVersion == null || manifest.tdfVersion.isEmpty()) {
                            String nonAligned = nonAlignedSpecVersion(manifest);
                            if (nonAligned != null) {
                                manifest.tdfVersion = nonAligned;
                            }
                        }
                    }
                    return value;
                }
            };
        }

        /** The first non-empty string under the non-aligned name, root before payload, or null. */
        private static String nonAlignedSpecVersion(Manifest manifest) {
            String atRoot = nonEmptyString(manifest.nonAlignedSpecVersion);
            if (atRoot != null) {
                return atRoot;
            }
            return manifest.payload == null ? null : nonEmptyString(manifest.payload.nonAlignedSpecVersion);
        }

        private static String nonEmptyString(JsonElement element) {
            if (element == null || !element.isJsonPrimitive() || !element.getAsJsonPrimitive().isString()) {
                return null;
            }
            String value = element.getAsString();
            return value.isEmpty() ? null : value;
        }
    }

    static public class PolicyBinding {
        public String alg;
        public String hash;

        @Override
        public boolean equals(Object o) {
            if (this == o)
                return true;
            if (o == null || getClass() != o.getClass())
                return false;
            PolicyBinding that = (PolicyBinding) o;
            return Objects.equals(alg, that.alg) && Objects.equals(hash, that.hash);
        }

        @Override
        public int hashCode() {
            return Objects.hash(alg, hash);
        }
    }

    static public class KeyAccess {
        @SerializedName(value = "type")
        public String keyType;
        public String url;
        public String protocol;
        public String wrappedKey;
        @JsonAdapter(PolicyBindingSerializer.class)
        public Object policyBinding;

        public String encryptedMetadata;
        public String kid;
        public String sid;
        public String schemaVersion;
        public String ephemeralPublicKey;

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            KeyAccess keyAccess = (KeyAccess) o;
            return Objects.equals(keyType, keyAccess.keyType) && Objects.equals(url, keyAccess.url)
                    && Objects.equals(protocol, keyAccess.protocol) && Objects.equals(wrappedKey, keyAccess.wrappedKey)
                    && Objects.equals(policyBinding, keyAccess.policyBinding)
                    && Objects.equals(encryptedMetadata, keyAccess.encryptedMetadata)
                    && Objects.equals(kid, keyAccess.kid)
                    && Objects.equals(schemaVersion, keyAccess.schemaVersion)
                    && Objects.equals(ephemeralPublicKey, keyAccess.ephemeralPublicKey);
        }

        @Override
        public int hashCode() {
            return Objects.hash(keyType, url, protocol, wrappedKey, policyBinding, encryptedMetadata, kid, schemaVersion, ephemeralPublicKey);
        }
    }

    static public class Method {
        public String algorithm;
        public String iv;
        @SerializedName(value = "isStreamable")
        public Boolean IsStreamable;

        @Override
        public boolean equals(Object o) {
            if (this == o)
                return true;
            if (o == null || getClass() != o.getClass())
                return false;
            Method method = (Method) o;
            return Objects.equals(algorithm, method.algorithm) && Objects.equals(iv, method.iv)
                    && Objects.equals(IsStreamable, method.IsStreamable);
        }

        @Override
        public int hashCode() {
            return Objects.hash(algorithm, iv, IsStreamable);
        }
    }

    static public class EncryptionInformation {
        @SerializedName(value = "type")
        public String keyAccessType;
        public String policy;

        @SerializedName(value = "keyAccess")
        public List<KeyAccess> keyAccessObj;
        public Method method;
        public IntegrityInformation integrityInformation;

        @Override
        public boolean equals(Object o) {
            if (this == o)
                return true;
            if (o == null || getClass() != o.getClass())
                return false;
            EncryptionInformation that = (EncryptionInformation) o;
            return Objects.equals(keyAccessType, that.keyAccessType) && Objects.equals(policy, that.policy)
                    && Objects.equals(keyAccessObj, that.keyAccessObj) && Objects.equals(method, that.method)
                    && Objects.equals(integrityInformation, that.integrityInformation);
        }

        @Override
        public int hashCode() {
            return Objects.hash(keyAccessType, policy, keyAccessObj, method, integrityInformation);
        }
    }

    static public class Payload {
        public String type;
        public String url;
        public String protocol;
        public String mimeType;
        public boolean isEncrypted;
        @DeserializeOnly
        @SerializedName("tdf_spec_version")
        JsonElement nonAlignedSpecVersion;

        @Override
        public boolean equals(Object o) {
            if (this == o)
                return true;
            if (o == null || getClass() != o.getClass())
                return false;
            Payload payload = (Payload) o;
            return Objects.equals(type, payload.type) && Objects.equals(url, payload.url)
                    && Objects.equals(protocol, payload.protocol) && Objects.equals(mimeType, payload.mimeType)
                    && Objects.equals(isEncrypted, payload.isEncrypted);
        }

        @Override
        public int hashCode() {
            return Objects.hash(type, url, protocol, mimeType, isEncrypted);
        }
    }

    static public class Binding {
        public String method;
        public String signature;

        @Override
        public boolean equals(Object o) {
            if (this == o)
                return true;
            if (o == null || getClass() != o.getClass())
                return false;
            Binding binding = (Binding) o;
            return Objects.equals(method, binding.method) && Objects.equals(signature, binding.signature);
        }

        @Override
        public int hashCode() {
            return Objects.hash(method, signature);
        }
    }

    static public class Assertion {
        public String id;
        public String type;
        public String scope;
        public String appliesToState;
        public AssertionConfig.Statement statement;
        public Binding binding;
        static public class HashValues {
            private final String assertionHash;
            private final String signature;

            public HashValues(String assertionHash, String signature) {
                this.assertionHash = assertionHash;
                this.signature = signature;
            }

            public String getAssertionHash() {
                return assertionHash;
            }

            public String getSignature() {
                return signature;
            }
        }

        @Override
        public boolean equals(Object o) {
            if (this == o)
                return true;
            if (o == null || getClass() != o.getClass())
                return false;
            Assertion that = (Assertion) o;
            return Objects.equals(id, that.id) && Objects.equals(type, that.type) &&
                    Objects.equals(scope, that.scope) && Objects.equals(appliesToState, that.appliesToState) &&
                    Objects.equals(statement, that.statement) && Objects.equals(binding, that.binding);
        }

        @Override
        public int hashCode() {
            return Objects.hash(id, type, scope, appliesToState, statement, binding);
        }

        public String hash() throws IOException {
            MessageDigest digest;
            try {
                digest = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                throw new SDKException("error creating SHA-256 message digest", e);
            }

            var assertionAsJson = gson.toJson(this);
            JsonCanonicalizer jc = new JsonCanonicalizer(assertionAsJson);
            return Hex.encodeHexString(digest.digest(jc.getEncodedUTF8()));
        }

        // Sign the assertion with the given hash and signature using the key.
        // It returns an error if the signing fails.
        // The assertion binding is updated with the method and the signature.
        public void sign(final HashValues hashValues, final AssertionConfig.AssertionKey assertionKey)
                throws KeyLengthException {
            // Build JWT claims
            final JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .claim(kAssertionHash, hashValues.assertionHash)
                    .claim(kAssertionSignature, hashValues.signature)
                    .build();

            // Prepare for signing
            SignedJWT signedJWT = createSignedJWT(claims, assertionKey);

            try {
                // Sign the JWT
                signedJWT.sign(createSigner(assertionKey));
            } catch (JOSEException e) {
                throw new SDKException("Error signing assertion", e);
            }

            // Store the binding and signature
            this.binding = new Binding();
            this.binding.method = AssertionConfig.BindingMethod.JWS.name();
            this.binding.signature = signedJWT.serialize();
        }

        // Checks the binding signature of the assertion and
        // returns the hash and the signature. It returns an error if the verification
        // fails.
        public Assertion.HashValues verify(AssertionConfig.AssertionKey assertionKey)
                throws ParseException, JOSEException, java.security.cert.CertificateException {
            if (binding == null) {
                throw new AssertionException("Binding is null in assertion", this.id);
            }

            String signatureString = binding.signature;
            binding = null; // Clear the binding after use

            SignedJWT signedJWT = SignedJWT.parse(signatureString);
            JWSHeader header = signedJWT.getHeader();
            JWSVerifier verifier = null;

            // Check for JWK in header
            if (header.getJWK() != null) {
                try {
                    verifier = createVerifier(header.getJWK());
                } catch (JOSEException e) {
                    throw new SDKException("Invalid JWK in JWT header", e);
                }
            }

            // Check for X.509 certificate chain in header
            if (verifier == null && header.getX509CertChain() != null && !header.getX509CertChain().isEmpty()) {
                try {
                    X509Certificate cert = X509CertUtils.parse(header.getX509CertChain().get(0).decode());
                    if (cert.getPublicKey() instanceof RSAPublicKey) {
                        verifier = createVerifier((RSAPublicKey) cert.getPublicKey());
                    } else {
                        throw new SDKException("Unsupported public key type in X.509 certificate");
                    }
                } catch (IllegalArgumentException e) {
                    throw new SDKException("Invalid Base64 in X.509 certificate in JWT header", e);
                }
            }


            if (verifier == null) {
                verifier = createVerifier(assertionKey);
            }


            if (!signedJWT.verify(verifier)) {
                throw new SDKException("Unable to verify assertion signature");
            }

            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            String assertionHash = claimsSet.getStringClaim(kAssertionHash);
            String signature = claimsSet.getStringClaim(kAssertionSignature);

            return new Assertion.HashValues(assertionHash, signature);
        }

        private SignedJWT createSignedJWT(final JWTClaimsSet claims, final AssertionConfig.AssertionKey assertionKey)
                throws SDKException {
            final JWSHeader.Builder headerBuilder;
            switch (assertionKey.alg) {
                case RS256:
                    headerBuilder = new JWSHeader.Builder(JWSAlgorithm.RS256);
                    break;
                case HS256:
                    headerBuilder = new JWSHeader.Builder(JWSAlgorithm.HS256);
                    break;
                default:
                    throw new SDKException("Unknown assertion key algorithm, error signing assertion");
            }

            if (assertionKey.jwk != null) {
                headerBuilder.jwk(assertionKey.jwk);
            }

            if (assertionKey.x5c != null) {
                headerBuilder.x509CertChain(assertionKey.x5c);
            }

            return new SignedJWT(headerBuilder.build(), claims);
        }

        private JWSSigner createSigner(final AssertionConfig.AssertionKey assertionKey)
                throws SDKException, KeyLengthException {
            switch (assertionKey.alg) {
                case RS256:
                    if (!(assertionKey.key instanceof PrivateKey)) {
                        throw new SDKException("Expected PrivateKey for RS256 algorithm");
                    }
                    return new RSASSASigner((PrivateKey) assertionKey.key);
                case HS256:
                    if (!(assertionKey.key instanceof byte[])) {
                        throw new SDKException("Expected byte[] key for HS256 algorithm");
                    }
                    return new MACSigner((byte[]) assertionKey.key);
                default:
                    throw new SDKException("Unknown signing algorithm: " + assertionKey.alg);
            }
        }

        private JWSVerifier createVerifier(AssertionConfig.AssertionKey assertionKey) throws JOSEException {
            switch (assertionKey.alg) {
                case RS256:
                    if (assertionKey.key instanceof JWK) {
                        return createVerifier((JWK) assertionKey.key);
                    } else if (assertionKey.key instanceof RSAPublicKey) {
                        return createVerifier((RSAPublicKey) assertionKey.key);
                    } else {
                        throw new SDKException("Expected JWK or RSAPublicKey for RS256 algorithm");
                    }
                case HS256:
                    return new MACVerifier((byte[]) assertionKey.key);
                default:
                    throw new SDKException("Unknown verify key, unable to verify assertion signature");
            }
        }

        private JWSVerifier createVerifier(JWK jwk) throws JOSEException {
            if (jwk instanceof com.nimbusds.jose.jwk.RSAKey) {
                return new RSASSAVerifier(jwk.toRSAKey());
            }
            throw new JOSEException("Unsupported JWK type: " + jwk.getKeyType() + ". Only RSA keys are supported.");
        }

        private JWSVerifier createVerifier(RSAPublicKey publicKey) {
            return new RSASSAVerifier(publicKey);
        }
    }

    public static class AssertionValueAdapter implements JsonDeserializer<AssertionConfig.Statement> {
        @Override
        public AssertionConfig.Statement deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
            if (!json.isJsonObject()) {
                throw new IllegalArgumentException(String.format("%s is not a JSON object", AssertionConfig.Statement.class.getName()));
            }
            var obj = json.getAsJsonObject();
            var statement = new AssertionConfig.Statement();
            if (obj.has("format")) {
                statement.format = obj.get("format").getAsString();
            }
            if (obj.has("schema")) {
                statement.schema = obj.get("schema").getAsString();
            }
            if (obj.has("value")) {
                var value = obj.get("value");
                if (value.isJsonPrimitive()) {
                    // it's already a primitive (hopefully string) so we don't need its escaped value here
                    statement.value = value.getAsString();
                } else {
                    statement.value = value.toString();
                }
            }
            return statement;
        }
    }

    public EncryptionInformation encryptionInformation;
    public Payload payload;
    public List<Assertion> assertions = new ArrayList<>();
    protected static Manifest readManifest(String manifestJson) {
        return readManifest(new StringReader(manifestJson));
    }

    /**
     * Parses a manifest without materializing it as a {@link String}, which a
     * manifest with tens of millions of segments cannot be.
     */
    protected static Manifest readManifest(java.io.Reader manifestJson) {
        Manifest result;
        try {
            result = gson.fromJson(manifestJson, Manifest.class);
        } catch (JsonParseException e) {
            if (e.getCause() instanceof IOException) {
                throw new SDKException("error reading manifest from zip file", (IOException) e.getCause());
            }
            throw e;
        }
        if (result == null) {
            throw new IllegalArgumentException("Manifest is empty");
        }
        validateManifest(result);
        return result;
    }

    private static void validateManifest(Manifest result) {
        if (result.assertions == null) {
            result.assertions = new ArrayList<>();
        }

        requireManifestField(result.payload, "Manifest with null payload");
        requireManifestField(result.encryptionInformation, "Manifest with null encryptionInformation");

        var encryptionInformation = result.encryptionInformation;
        requireManifestField(encryptionInformation.integrityInformation, "Manifest with null integrityInformation");
        requireManifestField(encryptionInformation.keyAccessObj, "Manifest with null keyAccessObj");
        requireManifestField(encryptionInformation.policy, "Manifest with null policy");

        var integrityInformation = encryptionInformation.integrityInformation;
        requireManifestField(integrityInformation.rootSignature, "Manifest with null rootSignature");
        requireManifestField(integrityInformation.segments, "Manifest with null segments");

        var rootSignature = integrityInformation.rootSignature;
        if (rootSignature.algorithm == null || rootSignature.signature == null) {
            throw new IllegalArgumentException("Manifest with invalid rootSignature");
        }

        validateSegments(integrityInformation.segments);
        validateKeyAccess(encryptionInformation.keyAccessObj);
    }

    private static void requireManifestField(Object field, String message) {
        if (field == null) {
            throw new IllegalArgumentException(message);
        }
    }

    private static void validateSegments(List<Segment> segments) {
        // Segments rejects null segments and hashes as it is built, so only the
        // fallback representation needs checking here.
        if (!(segments instanceof Segments)) {
            for (Manifest.Segment segment : segments) {
                if (segment == null || segment.hash == null) {
                    throw new IllegalArgumentException("Invalid integrity segment");
                }
            }
        }
    }

    private static void validateKeyAccess(List<KeyAccess> keyAccessObjects) {
        for (Manifest.KeyAccess keyAccess : keyAccessObjects) {
            if (keyAccess == null) {
                throw new IllegalArgumentException("Invalid null KeyAccess in manifest");
            } else if (keyAccess.url == null) {
                throw new IllegalArgumentException("Invalid KeyAccess with null url in manifest");
            }
        }
    }

    static PolicyObject decodePolicyObject(Manifest manifest) {
        var policyBase64 = manifest.encryptionInformation.policy;
        var policyBytes = Base64.getDecoder().decode(policyBase64);
        var policyJson = new String(policyBytes, StandardCharsets.UTF_8);

        return gson.fromJson(policyJson, PolicyObject.class);
    }
}
