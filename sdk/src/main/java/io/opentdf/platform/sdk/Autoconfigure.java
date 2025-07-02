package io.opentdf.platform.sdk;

import com.connectrpc.ResponseMessageKt;
import io.opentdf.platform.policy.Algorithm;
import io.opentdf.platform.policy.Attribute;
import io.opentdf.platform.policy.AttributeRuleTypeEnum;
import io.opentdf.platform.policy.AttributeValueSelector;
import io.opentdf.platform.policy.KasPublicKeyAlgEnum;
import io.opentdf.platform.policy.KeyAccessServer;
import io.opentdf.platform.policy.SimpleKasKey;
import io.opentdf.platform.policy.Value;
import io.opentdf.platform.policy.attributes.AttributesServiceClientInterface;
import io.opentdf.platform.policy.attributes.GetAttributeValuesByFqnsRequest;
import io.opentdf.platform.policy.attributes.GetAttributeValuesByFqnsResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.StringJoiner;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * The RuleType class defines a set of constants that represent various types of attribute rules.
 * These constants are used to specify the nature and behavior of attribute rules in the context
 * of key management and policy enforcement.
 */
class RuleType {
    public static final String HIERARCHY = "hierarchy";
    public static final String ALL_OF = "allOf";
    public static final String ANY_OF = "anyOf";
    public static final String UNSPECIFIED = "unspecified";
    public static final String EMPTY_TERM = "DEFAULT";
}

/**
 * The Autoconfigure class provides methods for configuring and retrieving
 * grants related to attribute values and KAS (Key Access Server) keys.
 * This class includes functionality to create granter instances based on
 * attributes either from a list of attribute values or from a service.
 */
class Autoconfigure {

    private static Logger logger = LoggerFactory.getLogger(Autoconfigure.class);

    static class KeySplitStep {
        final String kas;
        final String splitID;
        final String kid;

        KeySplitStep(String kas, String splitId) {
            this(kas, splitId, null);
        }

        KeySplitStep(String kas, String splitId, @Nullable String kid) {
            this.kas = Objects.requireNonNull(kas);
            this.splitID = Objects.requireNonNull(splitId);
            this.kid = kid;
        }

        @Override
        public boolean equals(Object o) {
            if (o == null || getClass() != o.getClass()) return false;
            KeySplitStep that = (KeySplitStep) o;
            return Objects.equals(kas, that.kas) && Objects.equals(splitID, that.splitID) && Objects.equals(kid, that.kid);
        }

        @Override
        public int hashCode() {
            return Objects.hash(kas, splitID, kid);
        }

        @Override
        public String toString() {
            return "KeySplitStep{" +
                    "kas='" + kas + '\'' +
                    ", splitID='" + splitID + '\'' +
                    ", kid='" + kid + '\'' +
                    '}';
        }
    }

    // Utility class for an attribute name FQN.
    static class AttributeNameFQN {
        private final String url;
        private final String key;

        public AttributeNameFQN(String url) throws AutoConfigureException {
            Pattern pattern = Pattern.compile("^(https?://[\\w./-]+)/attr/([^/\\s]*)$");
            Matcher matcher = pattern.matcher(url);
            if (!matcher.find() || matcher.group(1) == null || matcher.group(2) == null) {
                throw new AutoConfigureException("invalid type: attribute regex fail");
            }

            try {
                URLDecoder.decode(matcher.group(2), StandardCharsets.UTF_8);
            } catch (Exception e) {
                throw new AutoConfigureException("invalid type: error in attribute name [" + matcher.group(2) + "]");
            }

            this.url = url;
            this.key = url.toLowerCase();
        }

        @Override
        public String toString() {
            return url;
        }

        public AttributeValueFQN select(String value) throws AutoConfigureException {
            String newUrl = String.format("%s/value/%s", url, URLEncoder.encode(value, StandardCharsets.UTF_8));
            return new AttributeValueFQN(newUrl);
        }

        public String prefix() {
            return url;
        }

        public String getKey() {
            return key;
        }

        public String authority() throws AutoConfigureException {
            Pattern pattern = Pattern.compile("^(https?://[\\w./-]+)/attr/[^/\\s]*$");
            Matcher matcher = pattern.matcher(url);
            if (!matcher.find()) {
                throw new AutoConfigureException("invalid type");
            }
            return matcher.group(1);
        }

        public String name() throws AutoConfigureException {
            Pattern pattern = Pattern.compile("^https?://[\\w./-]+/attr/([^/\\s]*)$");
            Matcher matcher = pattern.matcher(url);
            if (!matcher.find()) {
                throw new AutoConfigureException("invalid attribute");
            }
            try {
                return URLDecoder.decode(matcher.group(1), StandardCharsets.UTF_8.name());
            } catch (Exception e) {
                throw new AutoConfigureException("invalid type");
            }
        }
    }

    // Utility class for an attribute value FQN.
    static class AttributeValueFQN {
        private final String url;
        private final String key;

        public AttributeValueFQN(String url) throws AutoConfigureException {
            Pattern pattern = Pattern.compile("^(https?://[\\w./-]+)/attr/(\\S*)/value/(\\S*)$");
            Matcher matcher = pattern.matcher(url);
            if (!matcher.find() || matcher.group(1) == null || matcher.group(2) == null || matcher.group(3) == null) {
                throw new AutoConfigureException("invalid type: attribute regex fail for [" + url + "]");
            }

            try {
                URLDecoder.decode(matcher.group(2), StandardCharsets.UTF_8.name());
                URLDecoder.decode(matcher.group(3), StandardCharsets.UTF_8.name());
            } catch (UnsupportedEncodingException | IllegalArgumentException e) {
                throw new AutoConfigureException("invalid type: error in attribute or value");
            }

            this.url = url;
            this.key = url.toLowerCase();
        }

        @Override
        public String toString() {
            return url;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || !(obj instanceof AttributeValueFQN)) {
                return false;
            }
            AttributeValueFQN afqn = (AttributeValueFQN) obj;
            if (this.key.equals(afqn.key)) {
                return true;
            }
            return false;
        }

        @Override
        public int hashCode() {
            return Objects.hash(key);
        }

        String getKey() {
            return key;
        }

        String authority() {
            Pattern pattern = Pattern.compile("^(https?://[\\w./-]+)/attr/\\S*/value/\\S*$");
            Matcher matcher = pattern.matcher(url);
            if (!matcher.find()) {
                throw new RuntimeException("invalid type");
            }
            return matcher.group(1);
        }

        AttributeNameFQN prefix() throws AutoConfigureException {
            Pattern pattern = Pattern.compile("^(https?://[\\w./-]+/attr/\\S*)/value/\\S*$");
            Matcher matcher = pattern.matcher(url);
            if (!matcher.find()) {
                throw new RuntimeException("invalid type");
            }
            return new AttributeNameFQN(matcher.group(1));
        }

        String value() {
            Pattern pattern = Pattern.compile("^https?://[\\w./-]+/attr/\\S*/value/(\\S*)$");
            Matcher matcher = pattern.matcher(url);
            if (!matcher.find()) {
                throw new RuntimeException("invalid type");
            }
            try {
                return URLDecoder.decode(matcher.group(1), StandardCharsets.UTF_8.name());
            } catch (UnsupportedEncodingException | IllegalArgumentException e) {
                throw new RuntimeException("invalid type", e);
            }
        }

        String name() {
            Pattern pattern = Pattern.compile("^https?://[\\w./-]+/attr/(\\S*)/value/\\S*$");
            Matcher matcher = pattern.matcher(url);
            if (!matcher.find()) {
                throw new RuntimeException("invalid attributeInstance");
            }
            try {
                return URLDecoder.decode(matcher.group(1), StandardCharsets.UTF_8);
            } catch (IllegalArgumentException e) {
                throw new RuntimeException("invalid attributeInstance", e);
            }
        }
    }

    static class KeyAccessGrant {
        public Attribute attr;
        public List<String> kases;

        public KeyAccessGrant(Attribute attr, List<String> kases) {
            this.attr = attr;
            this.kases = kases;
        }
    }

    // Structure capable of generating a split plan from a given set of data tags.
    static class Granter {
        private final List<AttributeValueFQN> policy;
        private final Map<String, KeyAccessGrant> grants = new HashMap<>();
        private final Map<String, List<Config.KASInfo>> mappedKeys = new HashMap<>();
        private boolean hasGrants = false;
        private boolean hasMappedKeys = false;

        Granter(List<AttributeValueFQN> policy) {
            this.policy = policy;
        }

        Map<String, KeyAccessGrant> getGrants() {
            return new HashMap<>(grants);
        }

        List<AttributeValueFQN> getPolicy() {
            return policy;
        }

        boolean addAllGrants(AttributeValueFQN fqn, List<KeyAccessServer> granted, List<SimpleKasKey> mapped, Attribute attr, KASKeyCache keyCache) {
            boolean foundMappedKey = false;
            for (var mappedKey: mapped) {
                foundMappedKey = true;
                mappedKeys.computeIfAbsent(fqn.key, k -> new ArrayList<>()).add(Config.KASInfo.fromSimpleKasKey(mappedKey));
                grants.computeIfAbsent(fqn.key, k -> new KeyAccessGrant(attr, new ArrayList<>())).kases.add(mappedKey.getKasUri());
            }

            if (foundMappedKey) {
                hasMappedKeys = true;
                return true;
            }

            boolean foundGrantedKey = false;
            for (var grantedKey: granted) {
                foundGrantedKey = true;
                grants.computeIfAbsent(fqn.key, k -> new KeyAccessGrant(attr, new ArrayList<>())).kases.add(grantedKey.getUri());
                if (!grantedKey.getKasKeysList().isEmpty()) {
                    for (var kas : grantedKey.getKasKeysList()) {
                        mappedKeys.computeIfAbsent(fqn.key, k -> new ArrayList<>()).add(Config.KASInfo.fromSimpleKasKey(kas));
                    }
                    continue;
                }
                var cachedGrantKeys = grantedKey.getPublicKey().getCached().getKeysList();
                if (cachedGrantKeys.isEmpty()) {
                    logger.debug("no keys cached in policy service");
                    continue;
                }
                for (var cachedGrantKey: cachedGrantKeys) {
                    var mappedKey = new Config.KASInfo();
                    mappedKey.URL = grantedKey.getUri();
                    mappedKey.KID = cachedGrantKey.getKid();
                    mappedKey.Algorithm = Autoconfigure.algProto2String(cachedGrantKey.getAlg());
                    mappedKey.PublicKey = cachedGrantKey.getPem();
                    mappedKey.Default = false;
                    mappedKeys.computeIfAbsent(fqn.key, k -> new ArrayList<>()).add(mappedKey);
                }
            }

            if (!grants.containsKey(fqn.key)) {
                grants.put(fqn.key, new KeyAccessGrant(attr, new ArrayList<>()));
            }

            if (foundGrantedKey) {
                hasGrants = true;
            }
            return foundGrantedKey;
        }

        KeyAccessGrant byAttribute(AttributeValueFQN fqn) {
            return grants.get(fqn.key);
        }

        List<KeySplitStep> getSplits(List<String> defaultKases, Supplier<String> genSplitID, Supplier<Optional<SimpleKasKey>> baseKeySupplier) throws AutoConfigureException {
            if (hasMappedKeys) {
                logger.debug("generating plan from mapped keys");
                return planFromAttributes(genSplitID);
            }
            if (hasGrants) {
                logger.debug("generating plan from grants");
                return plan(genSplitID);
            }

            var baseKey = baseKeySupplier.get();
            if (baseKey.isPresent()) {
                var key = baseKey.get();
                String kas = key.getKasUri();
                String splitID = "";
                String kid = key.getPublicKey().getKid();
                return Collections.singletonList(new KeySplitStep(kas, splitID, kid));
            }

            logger.warn("no grants or mapped keys found, generating plan from default KASes. this is deprecated");
            // this is a little bit weird because we don't take into account the KIDs here. This is the way
            // that it works in
            return generatePlanFromDefaultKases(defaultKases, genSplitID);
        }

        @Nonnull
        List<KeySplitStep> plan(Supplier<String> genSplitID)
                throws AutoConfigureException {
            AttributeBooleanExpression b = constructAttributeBoolean();
            BooleanKeyExpression k = insertKeysForAttribute(b);
            if (k == null) {
                throw new AutoConfigureException("Error inserting keys for attribute");
            }

            k = k.reduce();
            int l = k.size();
            if (l == 0) {
                throw new IllegalStateException("generated an empty plan");
            }

            List<KeySplitStep> steps = new ArrayList<>();
            for (KeyClause v : k.values) {
                String splitID = (l > 1) ? genSplitID.get() : "";
                for (PublicKeyInfo o : v.values) {
                    steps.add(new KeySplitStep(o.kas, splitID));
                }
            }
            return steps;
        }

        @Nonnull
        List<KeySplitStep> planFromAttributes(Supplier<String> genSplitID)
                throws AutoConfigureException {
            AttributeBooleanExpression b = constructAttributeBoolean();
            BooleanKeyExpression k = assignKeysTo(b);
            if (k == null) {
                throw new AutoConfigureException("Error assigning keys to attribute");
            }

            k = k.reduce();
            int l = k.size();
            if (l == 0) {
                return Collections.emptyList();
            }

            List<KeySplitStep> steps = new ArrayList<>();
            for (KeyClause v : k.values) {
                String splitID = (l > 1) ? genSplitID.get() : "";
                for (PublicKeyInfo o : v.values) {
                    steps.add(new KeySplitStep(o.kas, splitID, o.kid));
                }
            }
            return steps;
        }

        static List<KeySplitStep> generatePlanFromDefaultKases(List<String> defaultKas, Supplier<String> genSplitID) {
            if (defaultKas.isEmpty()) {
                throw new AutoConfigureException("no default KAS specified; required for grantless plans");
            } else if (defaultKas.size() == 1) {
                return Collections.singletonList(new KeySplitStep(defaultKas.get(0), ""));
            } else {
                List<KeySplitStep> result = new ArrayList<>();
                for (String kas : defaultKas) {
                    result.add(new KeySplitStep(kas, genSplitID.get()));
                }
                return result;
            }
        }

        BooleanKeyExpression insertKeysForAttribute(AttributeBooleanExpression e) throws AutoConfigureException {
            List<KeyClause> kcs = new ArrayList<>(e.must.size());

            for (SingleAttributeClause clause : e.must) {
                List<PublicKeyInfo> kcv = new ArrayList<>(clause.values.size());

                for (AttributeValueFQN term : clause.values) {
                    KeyAccessGrant grant = byAttribute(term);
                    if (grant == null) {
                        throw new AutoConfigureException(String.format("no definition or grant found for [%s]", term));
                    }

                    List<String> kases = grant.kases;
                    if (kases.isEmpty()) {
                        // TODO: replace this with a reference to the base key
                        kases = List.of(RuleType.EMPTY_TERM);
                    }

                    for (String kas : kases) {
                        kcv.add(new PublicKeyInfo(kas));
                    }
                }

                String op = ruleToOperator(clause.def.getRule());
                if (op.equals(RuleType.UNSPECIFIED)) {
                    logger.warn("Unknown attribute rule type: " + clause);
                }

                kcs.add(new KeyClause(op, kcv));
            }

            return new BooleanKeyExpression(kcs);
        }

        BooleanKeyExpression assignKeysTo(AttributeBooleanExpression e) {
            var keyClauses = new ArrayList<KeyClause>();
            for (var clause : e.must) {
                ArrayList<PublicKeyInfo> keys = new ArrayList<>();
                if (clause.values.isEmpty()) {
                    logger.warn("No values found for attribute: " + clause.def.getFqn());
                    continue;
                }
                for (var value : clause.values) {
                    var mapped = mappedKeys.get(value.key);
                    if (mapped == null) {
                        logger.warn("No keys found for attribute value {} ", value);
                        continue;
                    }
                    for (var kasInfo : mapped) {
                        if (kasInfo.URL == null || kasInfo.URL.isEmpty()) {
                            logger.warn("No KAS URL found for attribute value {}", value);
                            continue;
                        }
                        keys.add(new PublicKeyInfo(kasInfo.URL, kasInfo.KID));
                    }
                }

                String op = ruleToOperator(clause.def.getRule());
                if (op.equals(RuleType.UNSPECIFIED)) {
                    logger.warn("Unknown attribute rule type {}", op);
                }

                keyClauses.add(new KeyClause(op, keys));
            }

            return new BooleanKeyExpression(keyClauses);
        }

        /**
         * Constructs an AttributeBooleanExpression from the policy, splitting each attribute
         * into its own clause. Each clause contains the attribute definition and a list of
         * values.
         * @return
         * @throws AutoConfigureException
         */
        AttributeBooleanExpression constructAttributeBoolean() throws AutoConfigureException {
            Map<String, SingleAttributeClause> prefixes = new HashMap<>();
            List<String> sortedPrefixes = new ArrayList<>();
            for (AttributeValueFQN aP : policy) {
                AttributeNameFQN a = aP.prefix();
                SingleAttributeClause clause = prefixes.get(a.getKey());
                if (clause != null) {
                    clause.values.add(aP);
                } else if (byAttribute(aP) != null) {
                    var x = new SingleAttributeClause(byAttribute(aP).attr,
                            new ArrayList<>(Arrays.asList(aP)));
                    prefixes.put(a.getKey(), x);
                    sortedPrefixes.add(a.getKey());
                }
            }

            List<SingleAttributeClause> must = sortedPrefixes.stream()
                    .map(prefixes::get)
                    .collect(Collectors.toList());

            return new AttributeBooleanExpression(must);
        }

        static class SingleAttributeClause {

            private Attribute def;
            private List<AttributeValueFQN> values;

            public SingleAttributeClause(Attribute def, List<AttributeValueFQN> values) {
                this.def = def;
                this.values = values;
            }
        }

        static class AttributeBooleanExpression {

            private final List<SingleAttributeClause> must;

            public AttributeBooleanExpression(List<SingleAttributeClause> must) {
                this.must = must;
            }

            @Override
            public String toString() {
                if (must == null || must.isEmpty()) {
                    return "∅";
                }

                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < must.size(); i++) {
                    SingleAttributeClause clause = must.get(i);
                    if (i > 0) {
                        sb.append("&");
                    }

                    List<AttributeValueFQN> values = clause.values;
                    if (values == null || values.isEmpty()) {
                        sb.append(clause.def.getFqn());
                    } else if (values.size() == 1) {
                        sb.append(values.get(0).toString());
                    } else {
                        sb.append(clause.def.getFqn());
                        sb.append("/value/{");

                        StringJoiner joiner = new StringJoiner(",");
                        for (AttributeValueFQN v : values) {
                            joiner.add(v.value());
                        }
                        sb.append(joiner.toString());
                        sb.append("}");
                    }
                }
                return sb.toString();
            }

        }

        static class PublicKeyInfo implements Comparable<PublicKeyInfo> {
            final String kas;
            final String kid;

            PublicKeyInfo(String kas) {
                this(kas, null);
            }

            PublicKeyInfo(String kas, String kid) {
                this.kas = kas;
                this.kid = kid;
            }

            String getKas() {
                return kas;
            }

            @Override
            public boolean equals(Object o) {
                if (o == null || getClass() != o.getClass()) return false;
                PublicKeyInfo that = (PublicKeyInfo) o;
                return Objects.equals(kas, that.kas) && Objects.equals(kid, that.kid);
            }

            @Override
            public int hashCode() {
                return Objects.hash(kas, kid);
            }

            @Override
            public String toString() {
                return "PublicKeyInfo{" +
                        "kas='" + kas + '\'' +
                        ", kid='" + kid + '\'' +
                        '}';
            }

            @Override
            public int compareTo(PublicKeyInfo o) {
                if (this.kas.equals(o.kas)) {
                    if (this.kid == null && o.kid == null) {
                        return 0;
                    }
                    if (this.kid == null) {
                        return -1;
                    }
                    if (o.kid == null) {
                        return 1;
                    }
                    return this.kid.compareTo(o.kid);
                } else {
                    return this.kas.compareTo(o.kas);
                }
            }
        }

        static class KeyClause {
            private final String operator;
            private final List<PublicKeyInfo> values;

            public KeyClause(String operator, List<PublicKeyInfo> values) {
                this.operator = operator;
                this.values = values;
            }

            @Override
            public String toString() {
                if (values.size() == 1 && values.get(0).getKas().equals(RuleType.EMPTY_TERM)) {
                    return "[" + RuleType.EMPTY_TERM + "]";
                }
                if (values.size() == 1) {
                    return "(" + values.get(0).getKas() + ")";
                }

                StringBuilder sb = new StringBuilder();
                sb.append("(");
                String op = "⋀";
                if (operator.equals(RuleType.ANY_OF)) {
                    op = "⋁";
                }

                for (int i = 0; i < values.size(); i++) {
                    if (i > 0) {
                        sb.append(op);
                    }
                    sb.append(values.get(i).getKas());
                }
                sb.append(")");

                return sb.toString();
            }
        }

        static class BooleanKeyExpression {
            private final List<KeyClause> values;

            public BooleanKeyExpression(List<KeyClause> values) {
                this.values = values;
            }

            @Override
            public String toString() {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < values.size(); i++) {
                    if (i > 0) {
                        sb.append("&");
                    }
                    sb.append(values.get(i).toString());
                }
                return sb.toString();
            }

            public int size() {
                int count = 0;
                for (KeyClause v : values) {
                    count += v.values.size();
                }
                return count;
            }

            public BooleanKeyExpression reduce() {
                List<Disjunction> conjunction = new ArrayList<>();
                for (KeyClause v : values) {
                    if (v.operator.equals(RuleType.ANY_OF)) {
                        Disjunction terms = sortedNoDupes(v.values);
                        if (!terms.isEmpty() && !within(conjunction, terms)) {
                            conjunction.add(terms);
                        }
                    } else {
                        for (PublicKeyInfo k : v.values) {
                            if (k.getKas().equals(RuleType.EMPTY_TERM)) {
                                continue;
                            }
                            Disjunction terms = new Disjunction();
                            terms.add(k);
                            if (!within(conjunction, terms)) {
                                conjunction.add(terms);
                            }
                        }
                    }
                }
                if (conjunction.isEmpty()) {
                    return new BooleanKeyExpression(new ArrayList<>());
                }

                List<KeyClause> newValues = new ArrayList<>();
                for (List<PublicKeyInfo> d : conjunction) {
                    List<PublicKeyInfo> pki = new ArrayList<>();
                    pki.addAll(d);
                    newValues.add(new KeyClause(RuleType.ANY_OF, pki));
                }
                return new BooleanKeyExpression(newValues);
            }

            public Disjunction sortedNoDupes(List<PublicKeyInfo> l) {
                Set<PublicKeyInfo> set = new HashSet<>();
                Disjunction list = new Disjunction();

                for (PublicKeyInfo e : l) {
                    if (!Objects.equals(e.getKas(), RuleType.EMPTY_TERM) && !set.contains(e)) {
                        set.add(e);
                        list.add(e);
                    }
                }

                Collections.sort(list);
                return list;
            }

        }

        static class Disjunction extends ArrayList<PublicKeyInfo> {

            public boolean less(Disjunction r) {
                int m = Math.min(this.size(), r.size());
                for (int i = 0; i < m; i++) {
                    int comparison = this.get(i).compareTo(r.get(i));
                    if (comparison < 0) {
                        return true;
                    }
                    if (comparison > 0) {
                        return false;
                    }
                }
                return this.size() < r.size();
            }

            public boolean equals(Object obj) {
                if (this == obj) {
                    return true;
                }
                if (obj == null || getClass() != obj.getClass()) {
                    return false;
                }
                Disjunction r = (Disjunction) obj;
                if (this.size() != r.size()) {
                    return false;
                }
                for (int i = 0; i < this.size(); i++) {
                    if (!this.get(i).equals(r.get(i))) {
                        return false;
                    }
                }
                return true;
            }

            @Override
            public int hashCode() {
                return super.hashCode();
            }

        }

        public static boolean within(List<Disjunction> list, Disjunction e) {
            for (Disjunction v : list) {
                if (e.equals(v)) {
                    return true;
                }
            }
            return false;
        }

        public static String ruleToOperator(AttributeRuleTypeEnum e) {
            switch (e) {
                case ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF:
                    return "allOf";
                case ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF:
                    return "anyOf";
                case ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY:
                    return "hierarchy";
                case ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED:
                    return "unspecified";
                default:
                    return "";
            }
        }

    }

    // Given a policy (list of data attributes or tags),
    // get a set of grants from attribute values to KASes.
    // Unlike `NewGranterFromService`, this works offline.
    public static Granter newGranterFromAttributes(KASKeyCache keyCache, Value... attrValues) throws AutoConfigureException {
        var attrsAndValues = Arrays.stream(attrValues).map(v -> {
            if (!v.hasAttribute()) {
                throw new AutoConfigureException("tried to use an attribute that is not initialized");
            }
            return GetAttributeValuesByFqnsResponse.AttributeAndValue.newBuilder()
                    .setValue(v)
                    .setAttribute(v.getAttribute())
                    .build();
        }).collect(Collectors.toList());

        return getGranter(keyCache, attrsAndValues);
    }

    // Gets a list of directory of KAS grants for a list of attribute FQNs
    public static Granter newGranterFromService(AttributesServiceClientInterface as, KASKeyCache keyCache, AttributeValueFQN... fqns) throws AutoConfigureException {
        GetAttributeValuesByFqnsRequest request = GetAttributeValuesByFqnsRequest.newBuilder()
                .addAllFqns(Arrays.stream(fqns).map(AttributeValueFQN::toString).collect(Collectors.toList()))
                .setWithValue(AttributeValueSelector.newBuilder().setWithKeyAccessGrants(true).build())
                .build();

        GetAttributeValuesByFqnsResponse av = ResponseMessageKt.getOrThrow(
                as.getAttributeValuesByFqnsBlocking(request, Collections.emptyMap()).execute()
        );

        return getGranter(keyCache, new ArrayList<>(av.getFqnAttributeValuesMap().values()));
    }

    private static Granter getGranter(KASKeyCache keyCache, List<GetAttributeValuesByFqnsResponse.AttributeAndValue> values) {
        Granter grants = new Granter(values.stream().map(GetAttributeValuesByFqnsResponse.AttributeAndValue::getValue).map(Value::getFqn).map(AttributeValueFQN::new).collect(Collectors.toList()));
        for (var attributeAndValue: values) {
            String fqnstr = attributeAndValue.getValue().getFqn();
            AttributeValueFQN fqn = new AttributeValueFQN(fqnstr);

            var value = attributeAndValue.getValue();
            var attribute = attributeAndValue.getAttribute();
            var namespace = attribute.getNamespace();


            if (grants.addAllGrants(fqn, value.getGrantsList(), value.getKasKeysList(), attribute, keyCache)) {
                storeKeysToCache(value.getGrantsList(), value.getKasKeysList(), keyCache);
                continue;
            }
            if (grants.addAllGrants(fqn, attribute.getGrantsList(), attribute.getKasKeysList(), attribute, keyCache)) {
                storeKeysToCache(attribute.getGrantsList(), attribute.getKasKeysList(), keyCache);
                continue;
            }
            storeKeysToCache(namespace.getGrantsList(), namespace.getKasKeysList(), keyCache);
            grants.addAllGrants(fqn, namespace.getGrantsList(), namespace.getKasKeysList(), attribute, keyCache);
        }

        return grants;
    }

    static void storeKeysToCache(List<KeyAccessServer> kases, List<SimpleKasKey> kasKeys, KASKeyCache keyCache) {
        if (keyCache == null) {
            return;
        }
        for (var kas : kases) {
            Config.KASInfo.fromKeyAccessServer(kas).forEach(keyCache::store);
        }
        kasKeys.stream().map(Config.KASInfo::fromSimpleKasKey).forEach(keyCache::store);
    }

    static String algProto2String(Algorithm e) {
        switch (e) {
            case ALGORITHM_EC_P521:
                return "ec:p521";
            case ALGORITHM_RSA_2048:
                return "rsa:2048";
            default:
                throw new IllegalArgumentException("Unknown algorithm: " + e);
        }
    }

    static String algProto2String(KasPublicKeyAlgEnum e) {
        switch (e) {
            case KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1:
                return "ec:secp256r1";
            case KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048:
                return "rsa:2048";
            case KAS_PUBLIC_KEY_ALG_ENUM_UNSPECIFIED:
            default:
                return "";
        }
    }

}
