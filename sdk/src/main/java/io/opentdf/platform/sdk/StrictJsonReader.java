package io.opentdf.platform.sdk;

import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

import java.io.FilterReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A strict {@link JsonReader} that applies the JSON profile of the ZTDF assertions specification
 * (Section 3) while the document streams past, so the checks see every member before Gson's
 * object model or a typed field can silently keep only one of two duplicates.
 * <p>
 * Gson keeps the last of two members with the same name, and other parsers keep the first, so
 * a manifest with duplicates means different things to different readers. This reader rejects:
 * <ul>
 * <li>duplicate member names in any object, compared after decoding escapes
 * ({@link AssertionFailureReason#DUPLICATE_MEMBER});</li>
 * <li>at every level of the specification's Table 3.2, from the manifest root down to each
 * assertion's {@code statement} and {@code binding}, a member name that is a case variant of a
 * name listed for that level, or two member names that are case variants of each other
 * ({@link AssertionFailureReason#AMBIGUOUS_MEMBER}); and</li>
 * <li>inside assertion objects, member names and strings with lone surrogates or Unicode
 * noncharacters, and numbers that overflow an IEEE 754 double
 * ({@link AssertionFailureReason#INVALID_JSON}).</li>
 * </ul>
 * Every value has to pass through one of the overridden methods, including values Gson skips
 * because the typed model has no field for them: {@link #skipValue()} walks them instead of
 * skipping them blind.
 * <p>
 * A failure outside any assertion throws at once. A failure inside an assertion is held until
 * the assertion object ends, and then thrown with the assertion's exact {@code id} when it has
 * one, so the first failure in document order is the one reported.
 */
final class StrictJsonReader extends JsonReader {

    /** What the top-level value is expected to be. */
    enum Mode {
        /** A whole manifest: the root object holds {@code assertions}. */
        MANIFEST,
        /** One assertion wire object. */
        ASSERTION,
        /** Any JSON: only duplicate member names are checked. */
        GENERIC
    }

    /**
     * What an open object or array is. The object kinds with a level name are the levels of the
     * specification's Table 3.2, each with its listed member names; the rest are not checked for
     * case variants.
     */
    private enum Kind {
        ROOT("manifest root", "assertions", "encryptionInformation", "payload", "schemaVersion", "tdf_spec_version"),
        PAYLOAD("payload", "type", "url", "protocol", "mimeType", "isEncrypted", "tdf_spec_version"),
        ENCRYPTION_INFORMATION("encryptionInformation", "type", "policy", "keyAccess", "method", "integrityInformation"),
        KEY_ACCESS("encryptionInformation.keyAccess[]", "type", "url", "protocol", "wrappedKey", "policyBinding",
                "encryptedMetadata", "kid", "sid", "schemaVersion", "ephemeralPublicKey"),
        POLICY_BINDING("encryptionInformation.keyAccess[].policyBinding", "alg", "hash"),
        METHOD("encryptionInformation.method", "algorithm", "iv", "isStreamable"),
        INTEGRITY_INFORMATION("encryptionInformation.integrityInformation", "rootSignature", "segmentHashAlg",
                "segmentSizeDefault", "encryptedSegmentSizeDefault", "segments"),
        ROOT_SIGNATURE("encryptionInformation.integrityInformation.rootSignature", "alg", "sig"),
        SEGMENT("encryptionInformation.integrityInformation.segments[]", "hash", "segmentSize", "encryptedSegmentSize"),
        ASSERTION("assertions[]", "id", "type", "scope", "appliesToState", "statement", "binding"),
        STATEMENT("assertions[].statement", "format", "schema", "value"),
        BINDING("assertions[].binding", "method", "signature", "bdo"),
        KEY_ACCESS_ARRAY(null),
        SEGMENTS_ARRAY(null),
        ASSERTIONS(null),
        OTHER(null);

        /** The level's name in Table 3.2, or null if this is not a checked level. */
        final String level;
        final List<String> listed;
        /** Each listed name by its folded form, so a lookup replaces a scan of the list. */
        final Map<String, String> listedByFold;

        Kind(String level, String... listed) {
            this.level = level;
            this.listed = List.of(listed);
            Map<String, String> byFold = new HashMap<>();
            for (String name : listed) {
                byFold.put(fold(name), name);
            }
            this.listedByFold = Map.copyOf(byFold);
        }

        boolean checked() {
            return level != null;
        }
    }

    /**
     * Names that are not rejected as case variants of a listed name (rule 1) although they are
     * one, by level. Java SDK releases up to 0.7.5 wrote {@code IsStreamable}; readers give it no
     * meaning. Two members that are case variants of each other are still rejected (rule 2).
     */
    private static final Map<String, List<String>> CASE_VARIANT_EXCEPTIONS =
            Map.of(Kind.METHOD.level, List.of("IsStreamable"));

    /** Table 3.2: the listed member names of each checked level, by level name. */
    static Map<String, List<String>> modelledNames() {
        Map<String, List<String>> table = new LinkedHashMap<>();
        for (Kind kind : Kind.values()) {
            if (kind.checked()) {
                table.put(kind.level, kind.listed);
            }
        }
        return table;
    }

    /** The rule 1 exceptions, by level name. */
    static Map<String, List<String>> caseVariantExceptions() {
        return CASE_VARIANT_EXCEPTIONS;
    }

    /** Above this many members an object's names move from a list scan to a hash set. */
    private static final int LINEAR_SCAN_LIMIT = 16;

    private static final class Frame {
        Kind kind;
        boolean inAssertion;
        /** The most recent member name read in this object; decides what a nested object is. */
        String lastName;
        /**
         * The member names seen so far: keyed by folded name at a checked level, so that one
         * lookup finds both exact duplicates and case variants, and by exact name elsewhere.
         */
        private final List<String> keys = new ArrayList<>();
        private final List<String> exactNames = new ArrayList<>();
        private Map<String, String> nameMap;
        // assertion frames only
        int idMembers;
        String idValue;
        AssertionFailureReason pendingReason;
        String pendingDetail;

        void reset(Kind kind, boolean inAssertion) {
            this.kind = kind;
            this.inAssertion = inAssertion;
            lastName = null;
            keys.clear();
            exactNames.clear();
            nameMap = null;
            idMembers = 0;
            idValue = null;
            pendingReason = null;
            pendingDetail = null;
        }

        /**
         * Records a member name under {@code key}.
         *
         * @return the exact name of an earlier member with the same key, or null if there is none
         */
        String addName(String key, String exactName) {
            if (nameMap != null) {
                return nameMap.putIfAbsent(key, exactName);
            }
            int earlier = keys.indexOf(key);
            if (earlier >= 0) {
                return exactNames.get(earlier);
            }
            keys.add(key);
            exactNames.add(exactName);
            if (keys.size() > LINEAR_SCAN_LIMIT) {
                nameMap = new HashMap<>();
                for (int i = 0; i < keys.size(); i++) {
                    nameMap.put(keys.get(i), exactNames.get(i));
                }
                keys.clear();
                exactNames.clear();
            }
            return null;
        }

        /** The assertion's {@code id} if it has exactly one, and it is a valid nonempty string. */
        String exactId() {
            if (idMembers != 1 || idValue == null || idValue.isEmpty() || iJsonStringProblem(idValue) != null) {
                return null;
            }
            return idValue;
        }
    }

    private final Mode mode;
    /** One entry per open object or array; entries are reused, so most objects allocate nothing. */
    private Frame[] frames = new Frame[16];
    private int depth;
    /** Index of the open assertion object's frame, or -1 outside any assertion. */
    private int assertionDepth = -1;

    StrictJsonReader(Reader in, Mode mode) {
        super(new LeadingByteOrderMarkCheck(in));
        this.mode = mode;
        setStrictness(Strictness.STRICT);
    }

    /**
     * Rejects text that starts with U+FEFF. JSON text has no byte order mark (RFC 8259 Section
     * 8.1), and Gson would otherwise skip one silently where other readers reject the document.
     */
    private static final class LeadingByteOrderMarkCheck extends FilterReader {
        private boolean checked;

        LeadingByteOrderMarkCheck(Reader in) {
            super(in);
        }

        @Override
        public int read(char[] buffer, int offset, int length) throws IOException {
            int read = super.read(buffer, offset, length);
            if (!checked && read > 0) {
                checked = true;
                if (buffer[offset] == '\uFEFF') {
                    throw new SDK.AssertionFailureException(null, AssertionFailureReason.INVALID_JSON,
                            "the JSON text starts with a byte order mark");
                }
            }
            return read;
        }

        @Override
        public int read() throws IOException {
            char[] one = new char[1];
            return read(one, 0, 1) < 0 ? -1 : one[0];
        }
    }

    @Override
    public void beginObject() throws IOException {
        super.beginObject();
        Frame parent = top();
        Kind kind;
        if (parent == null) {
            kind = mode == Mode.MANIFEST ? Kind.ROOT : mode == Mode.ASSERTION ? Kind.ASSERTION : Kind.OTHER;
        } else {
            kind = objectKind(parent.kind, parent.lastName);
        }
        push(kind, kind == Kind.ASSERTION || (parent != null && parent.inAssertion));
        if (kind == Kind.ASSERTION) {
            assertionDepth = depth - 1;
        }
    }

    @Override
    public void endObject() throws IOException {
        super.endObject();
        Frame frame = pop();
        if (frame.kind == Kind.ASSERTION) {
            assertionDepth = -1;
            if (frame.pendingReason != null) {
                throw new SDK.AssertionFailureException(frame.exactId(), frame.pendingReason, frame.pendingDetail);
            }
        }
    }

    @Override
    public void beginArray() throws IOException {
        super.beginArray();
        Frame parent = top();
        push(parent == null ? Kind.OTHER : arrayKind(parent.kind, parent.lastName),
                parent != null && parent.inAssertion);
    }

    @Override
    public void endArray() throws IOException {
        super.endArray();
        pop();
    }

    @Override
    public String nextName() throws IOException {
        String name = super.nextName();
        Frame frame = top();
        String folded = frame.kind.checked() ? fold(name) : name;
        String earlier = frame.addName(folded, name);
        if (earlier != null) {
            if (earlier.equals(name)) {
                fail(AssertionFailureReason.DUPLICATE_MEMBER, "duplicate member name \"" + name + "\" at " + getPath());
            } else {
                // rule 2
                fail(AssertionFailureReason.AMBIGUOUS_MEMBER, "member names \"" + earlier + "\" and \"" + name
                        + "\" are case variants of each other at " + getPath());
            }
        }
        if (frame.kind.checked()) {
            // rule 1
            String listed = frame.kind.listedByFold.get(folded);
            if (listed != null && !listed.equals(name)
                    && !CASE_VARIANT_EXCEPTIONS.getOrDefault(frame.kind.level, List.of()).contains(name)) {
                fail(AssertionFailureReason.AMBIGUOUS_MEMBER,
                        "member name \"" + name + "\" is a case variant of \"" + listed + "\" at " + getPath());
            }
        }
        if (frame.inAssertion) {
            String problem = iJsonStringProblem(name);
            if (problem != null) {
                fail(AssertionFailureReason.INVALID_JSON, "member name with " + problem + " at " + getPath());
            }
        }
        frame.lastName = name;
        if (frame.kind == Kind.ASSERTION && "id".equals(name)) {
            frame.idMembers++;
        }
        return name;
    }

    @Override
    public String nextString() throws IOException {
        JsonToken token = peek();
        String value = super.nextString();
        Frame frame = top();
        if (frame != null) {
            if (frame.inAssertion) {
                if (token == JsonToken.NUMBER) {
                    if (isOutOfDoubleRange(value)) {
                        fail(AssertionFailureReason.INVALID_JSON,
                                "number outside the IEEE 754 double range at " + getPreviousPath());
                    }
                } else {
                    String problem = iJsonStringProblem(value);
                    if (problem != null) {
                        fail(AssertionFailureReason.INVALID_JSON, "string with " + problem + " at " + getPreviousPath());
                    }
                }
            }
            if (frame.kind == Kind.ASSERTION && token == JsonToken.STRING && "id".equals(frame.lastName)) {
                frame.idValue = value;
            }
        }
        return value;
    }

    /**
     * Walks the value through the checking methods above rather than skipping it, so content
     * the typed model ignores is checked too. Nesting is bounded by the reader's nesting limit.
     */
    @Override
    public void skipValue() throws IOException {
        switch (peek()) {
            case BEGIN_ARRAY:
                beginArray();
                while (hasNext()) {
                    skipValue();
                }
                endArray();
                break;
            case BEGIN_OBJECT:
                beginObject();
                while (hasNext()) {
                    nextName();
                    skipValue();
                }
                endObject();
                break;
            case END_ARRAY:
                endArray();
                break;
            case END_OBJECT:
                endObject();
                break;
            case NAME:
                nextName();
                break;
            case STRING:
            case NUMBER:
                nextString();
                break;
            case BOOLEAN:
                nextBoolean();
                break;
            case NULL:
                nextNull();
                break;
            case END_DOCUMENT:
            default:
                // nothing to skip; JsonReader leaves the end of the document in place too
                break;
        }
    }

    /** True while the reader is inside an assertion object, as when a syntax error stopped it there. */
    boolean inAssertion() {
        return assertionDepth >= 0;
    }

    /** The exact {@code id} of the open assertion object, if one has been read; otherwise null. */
    String openAssertionId() {
        return assertionDepth >= 0 ? frames[assertionDepth].exactId() : null;
    }

    private void fail(AssertionFailureReason reason, String detail) {
        if (assertionDepth >= 0) {
            Frame assertion = frames[assertionDepth];
            if (assertion.pendingReason == null) {
                assertion.pendingReason = reason;
                assertion.pendingDetail = detail;
            }
            return;
        }
        throw new SDK.AssertionFailureException(null, reason, detail);
    }

    private Frame top() {
        return depth == 0 ? null : frames[depth - 1];
    }

    private void push(Kind kind, boolean inAssertion) {
        if (depth == frames.length) {
            frames = Arrays.copyOf(frames, depth * 2);
        }
        Frame frame = frames[depth];
        if (frame == null) {
            frame = new Frame();
            frames[depth] = frame;
        }
        frame.reset(kind, inAssertion);
        depth++;
    }

    private Frame pop() {
        return frames[--depth];
    }

    /** The kind of an object that is the value of {@code name} in, or an element of, {@code parent}. */
    private static Kind objectKind(Kind parent, String name) {
        switch (parent) {
            case ROOT:
                return "payload".equals(name) ? Kind.PAYLOAD
                        : "encryptionInformation".equals(name) ? Kind.ENCRYPTION_INFORMATION : Kind.OTHER;
            case ENCRYPTION_INFORMATION:
                return "method".equals(name) ? Kind.METHOD
                        : "integrityInformation".equals(name) ? Kind.INTEGRITY_INFORMATION : Kind.OTHER;
            case KEY_ACCESS_ARRAY:
                return Kind.KEY_ACCESS;
            case KEY_ACCESS:
                return "policyBinding".equals(name) ? Kind.POLICY_BINDING : Kind.OTHER;
            case INTEGRITY_INFORMATION:
                return "rootSignature".equals(name) ? Kind.ROOT_SIGNATURE : Kind.OTHER;
            case SEGMENTS_ARRAY:
                return Kind.SEGMENT;
            case ASSERTIONS:
                return Kind.ASSERTION;
            case ASSERTION:
                return "statement".equals(name) ? Kind.STATEMENT : "binding".equals(name) ? Kind.BINDING : Kind.OTHER;
            default:
                return Kind.OTHER;
        }
    }

    /** The kind of an array that is the value of {@code name} in {@code parent}. */
    private static Kind arrayKind(Kind parent, String name) {
        if (parent == Kind.ROOT && "assertions".equals(name)) {
            return Kind.ASSERTIONS;
        }
        if (parent == Kind.ENCRYPTION_INFORMATION && "keyAccess".equals(name)) {
            return Kind.KEY_ACCESS_ARRAY;
        }
        if (parent == Kind.INTEGRITY_INFORMATION && "segments".equals(name)) {
            return Kind.SEGMENTS_ARRAY;
        }
        return Kind.OTHER;
    }

    /**
     * {@code name} folded for case-variant comparison: ASCII letters to lower case, U+017F LATIN
     * SMALL LETTER LONG S to {@code s}, U+212A KELVIN SIGN to {@code k}, and every other code
     * point unchanged. Two different names are case variants exactly when their folded forms are
     * equal, which is Go's {@code strings.EqualFold} against an ASCII name, how Go's struct
     * decoder matches members. {@link String#equalsIgnoreCase} folds differently and must not be
     * used here.
     */
    static String fold(String name) {
        StringBuilder folded = null;
        for (int i = 0; i < name.length(); ) {
            int codePoint = name.codePointAt(i);
            int mapped;
            if (codePoint >= 'A' && codePoint <= 'Z') {
                mapped = codePoint + ('a' - 'A');
            } else if (codePoint == 0x017F) {
                mapped = 's';
            } else if (codePoint == 0x212A) {
                mapped = 'k';
            } else {
                mapped = codePoint;
            }
            if (mapped != codePoint && folded == null) {
                folded = new StringBuilder(name.length()).append(name, 0, i);
            }
            if (folded != null) {
                folded.appendCodePoint(mapped);
            }
            i += Character.charCount(codePoint);
        }
        return folded == null ? name : folded.toString();
    }

    /**
     * What makes {@code text} invalid in I-JSON (RFC 7493 Section 2.1), or null if nothing does:
     * a lone surrogate, or a Unicode noncharacter (U+FDD0 to U+FDEF, and the last two code points
     * of every plane).
     */
    static String iJsonStringProblem(String text) {
        for (int i = 0; i < text.length(); ) {
            char c = text.charAt(i);
            int codePoint;
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= text.length() || !Character.isLowSurrogate(text.charAt(i + 1))) {
                    return "a lone surrogate";
                }
                codePoint = Character.toCodePoint(c, text.charAt(i + 1));
                i += 2;
            } else if (Character.isLowSurrogate(c)) {
                return "a lone surrogate";
            } else {
                codePoint = c;
                i++;
            }
            if ((codePoint >= 0xFDD0 && codePoint <= 0xFDEF) || (codePoint & 0xFFFE) == 0xFFFE) {
                return "a Unicode noncharacter";
            }
        }
        return null;
    }

    /** True if the JSON number text parses to an infinite double, such as {@code 1e400}. */
    static boolean isOutOfDoubleRange(String numberText) {
        try {
            return Double.isInfinite(Double.parseDouble(numberText));
        } catch (NumberFormatException e) {
            // the reader only hands over well-formed JSON numbers, which always parse
            return true;
        }
    }
}
