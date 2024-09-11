package io.opentdf.platform.sdk;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.StringJoiner;
import java.util.concurrent.ExecutionException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Supplier;

import io.opentdf.platform.policy.KeyAccessServer;
import io.opentdf.platform.policy.attributes.AttributesServiceGrpc.AttributesServiceFutureStub;
import io.opentdf.platform.policy.attributes.GetAttributeValuesByFqnsRequest;
import io.opentdf.platform.policy.attributes.GetAttributeValuesByFqnsResponse;
import io.opentdf.platform.policy.attributes.GetAttributeValuesByFqnsResponse.AttributeAndValue;
import io.opentdf.platform.policy.Attribute;
import io.opentdf.platform.policy.Value;
import io.opentdf.platform.policy.KasPublicKey;
import io.opentdf.platform.policy.AttributeValueSelector;
import io.opentdf.platform.policy.AttributeRuleTypeEnum;
import io.opentdf.platform.policy.KasPublicKeyAlgEnum;

// Attribute rule types: operators!
class RuleType {
    public static final String HIERARCHY = "hierarchy";
    public static final String ALL_OF = "allOf";
    public static final String ANY_OF = "anyOf";
    public static final String UNSPECIFIED = "unspecified";
    public static final String EMPTY_TERM = "DEFAULT";
}

public class Autoconfigure {

    public static Logger logger = LoggerFactory.getLogger(Autoconfigure.class);

    public static class KeySplitStep {
        public String kas;
        public String splitID;

        public KeySplitStep(String kas, String splitId) {
            this.kas = kas;
            this.splitID = splitId;
        }

        @Override
        public String toString() {
            return "KeySplitStep{kas=" + this.kas + ", splitID=" + this.splitID + "}";
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || !(obj instanceof KeySplitStep)) {
                return false;
            }
            KeySplitStep ss = (KeySplitStep) obj;
            if ((this.kas.equals(ss.kas)) && (this.splitID.equals(ss.splitID))) {
                return true;
            }
            return false;
        }

        @Override
        public int hashCode() {
            return Objects.hash(kas, splitID);
        }
    }

    // Utility class for an attribute name FQN.
    public static class AttributeNameFQN {
        private final String url;
        private final String key;

        public AttributeNameFQN(String url) throws AutoConfigureException {
            Pattern pattern = Pattern.compile("^(https?://[\\w./-]+)/attr/([^/\\s]*)$");
            Matcher matcher = pattern.matcher(url);
            if (!matcher.find() || matcher.group(1) == null || matcher.group(2) == null) {
                throw new AutoConfigureException("invalid type: attribute regex fail");
            }

            try {
                URLDecoder.decode(matcher.group(2), StandardCharsets.UTF_8.name());
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
    public static class AttributeValueFQN {
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

        public String getKey() {
            return key;
        }

        public String authority() {
            Pattern pattern = Pattern.compile("^(https?://[\\w./-]+)/attr/\\S*/value/\\S*$");
            Matcher matcher = pattern.matcher(url);
            if (!matcher.find()) {
                throw new RuntimeException("invalid type");
            }
            return matcher.group(1);
        }

        public AttributeNameFQN prefix() throws AutoConfigureException {
            Pattern pattern = Pattern.compile("^(https?://[\\w./-]+/attr/\\S*)/value/\\S*$");
            Matcher matcher = pattern.matcher(url);
            if (!matcher.find()) {
                throw new RuntimeException("invalid type");
            }
            return new AttributeNameFQN(matcher.group(1));
        }

        public String value() {
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

        public String name() {
            Pattern pattern = Pattern.compile("^https?://[\\w./-]+/attr/(\\S*)/value/\\S*$");
            Matcher matcher = pattern.matcher(url);
            if (!matcher.find()) {
                throw new RuntimeException("invalid attributeInstance");
            }
            try {
                return URLDecoder.decode(matcher.group(1), StandardCharsets.UTF_8.name());
            } catch (UnsupportedEncodingException | IllegalArgumentException e) {
                throw new RuntimeException("invalid attributeInstance", e);
            }
        }
    }

    public static class KeyAccessGrant {
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

        public Granter(List<AttributeValueFQN> policy) {
            this.policy = policy;
        }

        public Map<String, KeyAccessGrant> getGrants() {
            return new HashMap<String, KeyAccessGrant>(grants);
        }

        public List<AttributeValueFQN> getPolicy() {
            return policy;
        }

        public void addGrant(AttributeValueFQN fqn, String kas, Attribute attr) {
            grants.computeIfAbsent(fqn.key, k -> new KeyAccessGrant(attr, new ArrayList<>())).kases.add(kas);
        }

        public void addAllGrants(AttributeValueFQN fqn, List<KeyAccessServer> gs, Attribute attr) {
            if (gs.isEmpty()) {
                grants.putIfAbsent(fqn.key, new KeyAccessGrant(attr, new ArrayList<>()));
            } else {
                for (KeyAccessServer g : gs) {
                    if (g != null) {
                        addGrant(fqn, g.getUri(), attr);
                    }
                }
            }
        }

        public KeyAccessGrant byAttribute(AttributeValueFQN fqn) {
            return grants.get(fqn.key);
        }

        public List<KeySplitStep> plan(List<String> defaultKas, Supplier<String> genSplitID)
                throws AutoConfigureException {
            AttributeBooleanExpression b = constructAttributeBoolean();
            BooleanKeyExpression k = insertKeysForAttribute(b);
            if (k == null) {
                throw new AutoConfigureException("Error inserting keys for attribute");
            }

            k = k.reduce();
            int l = k.size();
            if (l == 0) {
                // default behavior: split key across all default KAS
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

            List<KeySplitStep> steps = new ArrayList<>();
            for (KeyClause v : k.values) {
                String splitID = (l > 1) ? genSplitID.get() : "";
                for (PublicKeyInfo o : v.values) {
                    steps.add(new KeySplitStep(o.kas, splitID));
                }
            }
            return steps;
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
                        kases = List.of(RuleType.EMPTY_TERM);
                    }

                    for (String kas : kases) {
                        kcv.add(new PublicKeyInfo(kas));
                    }
                }

                String op = ruleToOperator(clause.def.getRule());
                if (op == RuleType.UNSPECIFIED) {
                    logger.warn("Unknown attribute rule type: " + clause);
                }

                KeyClause kc = new KeyClause(op, kcv);
                kcs.add(kc);
            }

            return new BooleanKeyExpression(kcs);
        }

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
                            new ArrayList<AttributeValueFQN>(Arrays.asList(aP)));
                    prefixes.put(a.getKey(), x);
                    sortedPrefixes.add(a.getKey());
                }
            }

            List<SingleAttributeClause> must = sortedPrefixes.stream()
                    .map(prefixes::get)
                    .collect(Collectors.toList());

            return new AttributeBooleanExpression(must);
        }

        static class AttributeMapping {

            private Map<AttributeNameFQN, Attribute> dict;

            public AttributeMapping() {
                this.dict = new HashMap<>();
            }

            public void put(Attribute ad) throws AutoConfigureException {
                if (this.dict == null) {
                    this.dict = new HashMap<>();
                }

                AttributeNameFQN prefix = new AttributeNameFQN(ad.getFqn());

                if (this.dict.containsKey(prefix)) {
                    throw new AutoConfigureException("Attribute prefix already found: [" + prefix.toString() + "]");
                }

                this.dict.put(prefix, ad);
            }

            public Attribute get(AttributeNameFQN prefix) throws AutoConfigureException {
                Attribute ad = this.dict.get(prefix);
                if (ad == null) {
                    throw new AutoConfigureException("Unknown attribute type: [" + prefix.toString() + "], not in ["
                            + this.dict.keySet().toString() + "]");
                }
                return ad;
            }

        }

        static class SingleAttributeClause {

            private Attribute def;
            private List<AttributeValueFQN> values;

            public SingleAttributeClause(Attribute def, List<AttributeValueFQN> values) {
                this.def = def;
                this.values = values;
            }
        }

        class AttributeBooleanExpression {

            private List<SingleAttributeClause> must;

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

        public class PublicKeyInfo {
            private String kas;

            public PublicKeyInfo(String kas) {
                this.kas = kas;
            }

            public String getKas() {
                return kas;
            }

            public void setKas(String kas) {
                this.kas = kas;
            }
        }

        public class KeyClause {
            private String operator;
            private List<PublicKeyInfo> values;

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

        public class BooleanKeyExpression {
            private List<KeyClause> values;

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
                            terms.add(k.getKas());
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
                for (List<String> d : conjunction) {
                    List<PublicKeyInfo> pki = new ArrayList<>();
                    for (String k : d) {
                        pki.add(new PublicKeyInfo(k));
                    }
                    newValues.add(new KeyClause(RuleType.ANY_OF, pki));
                }
                return new BooleanKeyExpression(newValues);
            }

            public Disjunction sortedNoDupes(List<PublicKeyInfo> l) {
                Set<String> set = new HashSet<>();
                Disjunction list = new Disjunction();

                for (PublicKeyInfo e : l) {
                    String kas = e.getKas();
                    if (!kas.equals(RuleType.EMPTY_TERM) && !set.contains(kas)) {
                        set.add(kas);
                        list.add(kas);
                    }
                }

                Collections.sort(list);
                return list;
            }

        }

        class Disjunction extends ArrayList<String> {

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

    // Gets a list of directory of KAS grants for a list of attribute FQNs
    public static Granter newGranterFromService(AttributesServiceFutureStub as, KASKeyCache keyCache,
            AttributeValueFQN... fqns) throws AutoConfigureException, InterruptedException, ExecutionException {
        String[] fqnsStr = new String[fqns.length];
        for (int i = 0; i < fqns.length; i++) {
            fqnsStr[i] = fqns[i].toString();
        }

        GetAttributeValuesByFqnsRequest request = GetAttributeValuesByFqnsRequest.newBuilder()
                .addAllFqns(Arrays.asList(fqnsStr))
                .setWithValue(AttributeValueSelector.newBuilder().setWithKeyAccessGrants(true).build())
                .build();

        GetAttributeValuesByFqnsResponse av;
        av = as.getAttributeValuesByFqns(request).get();

        Granter grants = new Granter(Arrays.asList(fqns));

        for (Map.Entry<String, GetAttributeValuesByFqnsResponse.AttributeAndValue> entry : av.getFqnAttributeValuesMap()
                .entrySet()) {
            String fqnstr = entry.getKey();
            AttributeAndValue pair = entry.getValue();

            AttributeValueFQN fqn;
            try {
                fqn = new AttributeValueFQN(fqnstr);
            } catch (Exception e) {
                return grants;
            }

            Attribute def = pair.getAttribute();
            Value v = pair.getValue();
            if (v != null && !v.getGrantsList().isEmpty()) {
                grants.addAllGrants(fqn, v.getGrantsList(), def);
                storeKeysToCache(v.getGrantsList(), keyCache);
            } else {
                if (def != null) {
                    grants.addAllGrants(fqn, def.getGrantsList(), def);
                    storeKeysToCache(def.getGrantsList(), keyCache);
                }
            }
        }

        return grants;
    }

    // Given a policy (list of data attributes or tags),
    // get a set of grants from attribute values to KASes.
    // Unlike `NewGranterFromService`, this works offline.
    public static Granter newGranterFromAttributes(Value... attrs) throws AutoConfigureException {
        List<AttributeValueFQN> policyList = new ArrayList<>(attrs.length);

        Granter grants = new Granter(policyList);

        for (Value v : attrs) {
            AttributeValueFQN fqn;
            try {
                fqn = new AttributeValueFQN(v.getFqn());
            } catch (Exception e) {
                return grants;
            }

            grants.policy.add(fqn);
            Attribute def = v.getAttribute();
            if (def == null) {
                throw new AutoConfigureException("No associated definition with value [" + fqn.toString() + "]");
            }

            grants.addAllGrants(fqn, def.getGrantsList(), def);
            grants.addAllGrants(fqn, v.getGrantsList(), def);
        }

        return grants;
    }

    static void storeKeysToCache(List<KeyAccessServer> kases, KASKeyCache keyCache) {
        for (KeyAccessServer kas : kases) {
            List<KasPublicKey> keys = kas.getPublicKey().getCached().getKeysList();
            if (keys.isEmpty()) {
                logger.debug("No cached key in policy service for KAS: " + kas.getUri());
                continue;
            }
            for (KasPublicKey ki : keys) {
                Config.KASInfo kasInfo = new Config.KASInfo();
                kasInfo.URL = kas.getUri();
                kasInfo.KID = ki.getKid();
                kasInfo.Algorithm = algProto2String(ki.getAlg());
                kasInfo.PublicKey = ki.getPem();
                keyCache.store(kasInfo);
            }
        }
    }

    private static String algProto2String(KasPublicKeyAlgEnum e) {
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
