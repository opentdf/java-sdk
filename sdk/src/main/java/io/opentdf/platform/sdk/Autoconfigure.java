package io.opentdf.platform.sdk;

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
import java.util.Set;
import java.util.StringJoiner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Supplier;

import io.opentdf.platform.policy.KeyAccessServer;
import io.opentdf.platform.policy.attributes.GetAttributeValuesByFqnsRequest;
import io.opentdf.platform.policy.attributes.GetAttributeValuesByFqnsResponse;
import io.opentdf.platform.policy.attributes.GetAttributeValuesByFqnsResponse.AttributeAndValue;
import io.opentdf.platform.policy.Attribute;
import io.opentdf.platform.policy.Value;
import io.opentdf.platform.policy.AttributeValueSelector;
import io.opentdf.platform.policy.AttributeRuleTypeEnum;

// Error handling class
class AutoConfigureException extends Exception {
    public AutoConfigureException(String message) {
        super(message);
    }
}

// Attribute rule types: operators!
class RuleTypes {
    public static final String HIERARCHY = "hierarchy";
    public static final String ALL_OF = "allOf";
    public static final String ANY_OF = "anyOf";
    public static final String UNSPECIFIED = "unspecified";
    public static final String EMPTY_TERM = "DEFAULT";
}


public class Autoconfigure {

    public static Logger logger = LoggerFactory.getLogger(TDF.class);

    public static class SplitStep {
        public String kas;
        public String splitID;

        public SplitStep(String kas, String splitId) {
            this.kas = kas;
            this.splitID = splitId;
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
            } catch (Exception e) {
                throw new AutoConfigureException("invalid type: error in attribute or value");
            }

            this.url = url;
            this.key = url.toLowerCase();
        }

        @Override
        public String toString() {
            return url;
        }

        public String getKey() {
            return key;
        }

        public String authority() throws AutoConfigureException {
            Pattern pattern = Pattern.compile("^(https?://[\\w./-]+)/attr/\\S*/value/\\S*$");
            Matcher matcher = pattern.matcher(url);
            if (!matcher.find()) {
                throw new AutoConfigureException("invalid type");
            }
            return matcher.group(1);
        }

        public AttributeNameFQN prefix() throws AutoConfigureException {
            Pattern pattern = Pattern.compile("^(https?://[\\w./-]+/attr/\\S*)/value/\\S*$");
            Matcher matcher = pattern.matcher(url);
            if (!matcher.find()) {
                throw new AutoConfigureException("invalid type");
            }
            return new AttributeNameFQN(matcher.group(1));
        }

        public String value() throws AutoConfigureException {
            Pattern pattern = Pattern.compile("^https?://[\\w./-]+/attr/\\S*/value/(\\S*)$");
            Matcher matcher = pattern.matcher(url);
            if (!matcher.find()) {
                throw new AutoConfigureException("invalid type");
            }
            try {
                return URLDecoder.decode(matcher.group(1), StandardCharsets.UTF_8.name());
            } catch (Exception e) {
                throw new AutoConfigureException("invalid type");
            }
        }

        public String name() throws AutoConfigureException {
            Pattern pattern = Pattern.compile("^https?://[\\w./-]+/attr/(\\S*)/value/\\S*$");
            Matcher matcher = pattern.matcher(url);
            if (!matcher.find()) {
                throw new AutoConfigureException("invalid attributeInstance");
            }
            try {
                return URLDecoder.decode(matcher.group(1), StandardCharsets.UTF_8.name());
            } catch (Exception e) {
                throw new AutoConfigureException("invalid attributeInstance");
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
    public static class Granter {
        private final List<AttributeValueFQN> policy;
        private Map<String, KeyAccessGrant> grants = new HashMap<>();

        public Granter(List<AttributeValueFQN> policy) {
            this.policy = policy;
        }

        public Granter(List<AttributeValueFQN> policy, Map<String, KeyAccessGrant> grants) {
            this.policy = policy;
            this.grants = grants;
        }

        public  Map<String, KeyAccessGrant> getGrants() {
            return grants;
        }

        public List<AttributeValueFQN> getPolicy() {
            return policy;
        }

        public void addGrant(AttributeValueFQN fqn, String kas, Attribute attr) {
            grants.computeIfAbsent(fqn.key, k -> new KeyAccessGrant(attr, new ArrayList<>()))
                .kases.add(kas);
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

        public interface StringOperator {
            public String op();
        }


        public List<SplitStep> plan(List<String> defaultKas, Supplier<String> genSplitID) throws Exception {
            AttributeBooleanExpression b = constructAttributeBoolean();
            BooleanKeyExpression k = insertKeysForAttribute(b);
            if (k == null) {
                throw new AutoConfigureException("Error inserting keys for attribute");
            }

            k = k.reduce();
            int l = k.len();
            if (l == 0) {
                // default behavior: split key across all default KAS
                if (defaultKas.isEmpty()) {
                    throw new AutoConfigureException("no default KAS specified; required for grantless plans");
                } else if (defaultKas.size() == 1) {
                    return Collections.singletonList(new SplitStep(defaultKas.get(0), ""));
                } else {
                    List<SplitStep> result = new ArrayList<>();
                    for (String kas : defaultKas) {
                        result.add(new SplitStep(kas, genSplitID.get()));
                    }
                    return result;
                }
            }

            List<SplitStep> steps = new ArrayList<>();
            for (KeyClause v : k.values) {
                String splitID = (l > 1) ? genSplitID.get() : "";
                for (PublicKeyInfo o : v.values) {
                    steps.add(new SplitStep(o.kas, splitID));
                }
            }
            return steps;
        }

        public BooleanKeyExpression insertKeysForAttribute(AttributeBooleanExpression e) throws Exception {
            List<KeyClause> kcs = new ArrayList<>(e.must.size());
    
            for (SingleAttributeClause clause : e.must) {
                List<PublicKeyInfo> kcv = new ArrayList<>(clause.values.size());
    
                for (AttributeValueFQN term : clause.values) {
                    KeyAccessGrant grant = byAttribute(term);
                    if (grant == null) {
                        throw new Exception(String.format("no definition or grant found for [%s]", term));
                    }
    
                    List<String> kases = grant.kases;
                    if (kases.isEmpty()) {
                        kases = List.of(RuleTypes.EMPTY_TERM);
                    }
    
                    for (String kas : kases) {
                        kcv.add(new PublicKeyInfo(kas));
                    }
                }
    
                String op = ruleToOperator(clause.def.getRule());
                if (op == RuleTypes.UNSPECIFIED) {
                    logger.warn("Unknown attribute rule type: " + clause);
                }
    
                KeyClause kc = new KeyClause(op, kcv);
                kcs.add(kc);
            }
    
            return new BooleanKeyExpression(kcs);
        }

        AttributeBooleanExpression constructAttributeBoolean() {
            Map<String, SingleAttributeClause> prefixes = new HashMap<>();
            List<String> sortedPrefixes = new ArrayList<>();
            for (AttributeValueFQN aP : policy) {
                try {
                    AttributeNameFQN a = aP.prefix();
                    String p = a.toString().toLowerCase();
                    SingleAttributeClause clause = prefixes.get(p);
                    if (clause != null) {
                        clause.values.add(aP);
                    } else if (byAttribute(aP) != null) {
                        var x = new SingleAttributeClause(byAttribute(aP).attr, Collections.singletonList(aP));
                        prefixes.put(p, x);
                        sortedPrefixes.add(p);
                    }
                } catch (AutoConfigureException e) {
                    // Handle exception
                }
            }

            List<SingleAttributeClause> must = sortedPrefixes.stream()
                    .map(prefixes::get)
                    .collect(Collectors.toList());

            return new AttributeBooleanExpression(must);
        }



        public class AttributeMapping {

            private Map<AttributeNameFQN, Attribute> dict;
        
            public AttributeMapping() {
                this.dict = new HashMap<>();
            }
        
            public void put(Attribute ad) throws Exception {
                if (this.dict == null) {
                    this.dict = new HashMap<>();
                }
        
                AttributeNameFQN prefix;
                try {
                    prefix = new AttributeNameFQN(ad.getFqn());
                } catch (Exception e) {
                    throw new Exception(e);
                }
        
                if (this.dict.containsKey(prefix)) {
                    throw new Exception("Attribute prefix already found: [" + prefix.toString() + "]");
                }
        
                this.dict.put(prefix, ad);
            }
        
            public Attribute get(AttributeNameFQN prefix) throws Exception {
                Attribute ad = this.dict.get(prefix);
                if (ad == null) {
                    throw new Exception("Unknown attribute type: [" + prefix.toString() + "], not in [" + this.dict.keySet().toString() + "]");
                }
                return ad;
            }

        }

        public class SingleAttributeClause {

            private Attribute def;
            private List<AttributeValueFQN> values;
        
            public SingleAttributeClause(Attribute def, List<AttributeValueFQN> values) {
                this.def = def;
                this.values = values;
            }
        }

        public class AttributeBooleanExpression {

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
                            try {
                                joiner.add(v.value());
                            } catch (AutoConfigureException e) {
                                // This shouldnt happen
                                joiner.add("");
                            }
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
                if (values.size() == 1 && values.get(0).getKas().equals(RuleTypes.EMPTY_TERM)) {
                    return "[" + RuleTypes.EMPTY_TERM + "]";
                }
                if (values.size() == 1) {
                    return "(" + values.get(0).getKas() + ")";
                }
        
                StringBuilder sb = new StringBuilder();
                sb.append("(");
                String op = "⋀";
                if (operator.equals(RuleTypes.ANY_OF)) {
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

            public int len() {
                int count = 0;
                for (KeyClause v : values) {
                    count += v.values.size();
                }
                return count;
            }

            public BooleanKeyExpression reduce() {
                List<Disjunction> conjunction = new ArrayList<>();
                for (KeyClause v : values) {
                    if (v.operator.equals("anyOf")) {  // Assuming "anyOf" is a constant in Java
                        Disjunction terms = sortedNoDupes(v.values);
                        if (!terms.isEmpty() && !within(conjunction, terms)) {
                            conjunction.add(terms);
                        }
                    } else {
                        for (PublicKeyInfo k : v.values) {
                            if (k.getKas().equals("emptyTerm")) {  // Assuming "emptyTerm" is a constant in Java
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
                    newValues.add(new KeyClause("anyOf", pki));  // Assuming "anyOf" is a constant in Java
                }
                return new BooleanKeyExpression(newValues);
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
        }

        public static boolean within(List<Disjunction> list, Disjunction e) {
            for (Disjunction v : list) {
                if (e.equals(v)) {
                    return true;
                }
            }
            return false;
        }

        public static Disjunction sortedNoDupes(List<PublicKeyInfo> l) {
            Set<String> set = new HashSet<>();
            Disjunction list = new Disjunction();

            for (PublicKeyInfo e : l) {
                String kas = e.getKas();
                if (!kas.equals(RuleTypes.EMPTY_TERM) && !set.contains(kas)) {
                    set.add(kas);
                    list.add(kas);
                }
            }

            Collections.sort(list);
            return list;
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
    public static Granter newGranterFromService(SDK.AttributesService as, AttributeValueFQN... fqns) throws Exception {
        String[] fqnsStr = new String[fqns.length];
        for (int i = 0; i < fqns.length; i++) {
            fqnsStr[i] = fqns[i].toString();
        }

        GetAttributeValuesByFqnsRequest request = GetAttributeValuesByFqnsRequest.newBuilder()
            .addAllFqns(Arrays.asList(fqnsStr))
            .setWithValue(AttributeValueSelector.newBuilder().setWithKeyAccessGrants(true).build())
            .build();

        GetAttributeValuesByFqnsResponse av;
        av = as.getAttributeValuesByFqn(request);

        Granter grants = new Granter(Arrays.asList(fqns), new HashMap<>());

        for (Map.Entry<String,GetAttributeValuesByFqnsResponse.AttributeAndValue> entry : av.getFqnAttributeValuesMap().entrySet()) {
            String fqnstr = entry.getKey();
            AttributeAndValue pair = entry.getValue();

            AttributeValueFQN fqn;
            try {
                fqn = new AttributeValueFQN(fqnstr);
            } catch (Exception e) {
                return grants;
            }

            Attribute def = pair.getAttribute();
            if (def != null) {
                grants.addAllGrants(fqn, def.getGrantsList(), def);
            }

            Value v = pair.getValue();
            if (v != null) {
                grants.addAllGrants(fqn, v.getGrantsList(), def);
            }
        }

        return grants;
    }

    // Given a policy (list of data attributes or tags),
    // get a set of grants from attribute values to KASes.
    // Unlike `NewGranterFromService`, this works offline.
    public static Granter newGranterFromAttributes(Value... attrs) throws Exception {
        List<AttributeValueFQN> policyList = new ArrayList<>(attrs.length);
        Map<String, KeyAccessGrant> grantsMap = new HashMap<>();

        Granter grants = new Granter(policyList, grantsMap);

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
                throw new Exception("No associated definition with value [" + fqn.toString() + "]");
            }

            grants.addAllGrants(fqn, def.getGrantsList(), def);
            grants.addAllGrants(fqn, v.getGrantsList(), def);
        }

        return grants;
    }

}
