package io.opentdf.platform.sdk;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import io.opentdf.platform.policy.Attribute;
import io.opentdf.platform.policy.Value;
import io.opentdf.platform.sdk.Autoconfigure.AttributeValueFQN;
import io.opentdf.platform.sdk.Autoconfigure.Granter.AttributeBooleanExpression;
import io.opentdf.platform.sdk.Autoconfigure.Granter.BooleanKeyExpression;
import io.opentdf.platform.sdk.Autoconfigure.Granter;
import io.opentdf.platform.sdk.Autoconfigure.SplitStep;
import io.opentdf.platform.policy.Namespace;
import io.opentdf.platform.policy.KeyAccessServer;
import io.opentdf.platform.policy.AttributeRuleTypeEnum;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AutoconfigureTest {

    private static final String KAS_AU = "http://kas.au/";
    private static final String KAS_CA = "http://kas.ca/";
    private static final String KAS_UK = "http://kas.uk/";
    private static final String KAS_NZ = "http://kas.nz/";
    private static final String KAS_US = "http://kas.us/";
    private static final String KAS_US_HCS = "http://hcs.kas.us/";
    private static final String KAS_US_SA = "http://si.kas.us/";
    private static final String AUTHORITY = "https://virtru.com/";

    private static Autoconfigure.AttributeNameFQN CLS;
    private static Autoconfigure.AttributeNameFQN N2K;
    private static Autoconfigure.AttributeNameFQN REL;

    private static Autoconfigure.AttributeValueFQN clsA;
    private static Autoconfigure.AttributeValueFQN clsS;
    private static Autoconfigure.AttributeValueFQN clsTS;
    private static Autoconfigure.AttributeValueFQN n2kHCS;
    private static Autoconfigure.AttributeValueFQN n2kInt;
    private static Autoconfigure.AttributeValueFQN n2kSI;
    private static Autoconfigure.AttributeValueFQN rel2can;
    private static Autoconfigure.AttributeValueFQN rel2gbr;
    private static Autoconfigure.AttributeValueFQN rel2nzl;
    private static Autoconfigure.AttributeValueFQN rel2usa;

    @BeforeAll
    public static void setup() throws AutoConfigureException {
        // Initialize the FQNs (Fully Qualified Names)
        CLS = new Autoconfigure.AttributeNameFQN("https://virtru.com/attr/Classification");
        N2K = new Autoconfigure.AttributeNameFQN("https://virtru.com/attr/Need%20to%20Know");
        REL = new Autoconfigure.AttributeNameFQN("https://virtru.com/attr/Releasable%20To");

        clsA = new Autoconfigure.AttributeValueFQN("https://virtru.com/attr/Classification/value/Allowed");
        clsS = new Autoconfigure.AttributeValueFQN("https://virtru.com/attr/Classification/value/Secret");
        clsTS = new Autoconfigure.AttributeValueFQN("https://virtru.com/attr/Classification/value/Top%20Secret");

        n2kHCS = new Autoconfigure.AttributeValueFQN("https://virtru.com/attr/Need%20to%20Know/value/HCS");
        n2kInt = new Autoconfigure.AttributeValueFQN("https://virtru.com/attr/Need%20to%20Know/value/INT");
        n2kSI = new Autoconfigure.AttributeValueFQN("https://virtru.com/attr/Need%20to%20Know/value/SI");

        rel2can = new Autoconfigure.AttributeValueFQN("https://virtru.com/attr/Releasable%20To/value/CAN");
        rel2gbr = new Autoconfigure.AttributeValueFQN("https://virtru.com/attr/Releasable%20To/value/GBR");
        rel2nzl = new Autoconfigure.AttributeValueFQN("https://virtru.com/attr/Releasable%20To/value/NZL");
        rel2usa = new Autoconfigure.AttributeValueFQN("https://virtru.com/attr/Releasable%20To/value/USA");
    }

    private static String spongeCase(String s) {
        final Pattern PATTERN = Pattern.compile("^(https?://[\\w./]+/attr/)([^/]*)(/value/)?(\\S*)?$");
        Matcher matcher = PATTERN.matcher(s);

        if (!matcher.matches()) {
            throw new IllegalArgumentException("Invalid input string");
        }

        StringBuilder sb = new StringBuilder();
        sb.append(matcher.group(1));

        String n = matcher.group(2);
        for (int i = 0; i < n.length(); i++) {
            String sub = n.substring(i, i + 1);
            if ((i & 1) == 1) {
                sb.append(sub.toUpperCase());
            } else {
                sb.append(sub);
            }
        }

        if (matcher.group(3) != null) {
            sb.append(matcher.group(3));
            String v = matcher.group(4);
            for (int i = 0; i < v.length(); i++) {
                String sub = v.substring(i, i + 1);
                if ((i & 1) == 1) {
                    sb.append(sub);
                } else {
                    sb.append(sub.toUpperCase());
                }
            }
        }
        return sb.toString();
    }

    private List<Value> valuesToPolicy(AttributeValueFQN... p) throws AutoConfigureException {
        List<Value> values = new ArrayList<>();
        for (AttributeValueFQN afqn : List.of(p)){
            values.add(mockValueFor(afqn));
        }
        return values;
    }

    private List<String> policyToStringKeys(List<AttributeValueFQN> policy) {
        return policy.stream()
            .map(AttributeValueFQN::getKey)
            .collect(Collectors.toList());
    }

    private Autoconfigure.AttributeValueFQN messUpV(Autoconfigure.AttributeValueFQN a) {
        try {
            return new Autoconfigure.AttributeValueFQN(spongeCase(a.toString()));
        } catch (Exception e) {
            throw new RuntimeException("Failed to create AttributeValueFQN", e);
        }
    }

    private Attribute mockAttributeFor(Autoconfigure.AttributeNameFQN fqn) {
        String key = fqn.getKey();
        if (key.equals(CLS.getKey())){
                return Attribute.newBuilder().setId("CLS").setNamespace(
                    Namespace.newBuilder().setId("v").setName("virtru.com").setFqn("https://virtru.com").build())
                    .setName("Classification").setRule(AttributeRuleTypeEnum.ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY).setFqn(fqn.toString()).build();
        }
        else if (key.equals(N2K.getKey())) {
            return Attribute.newBuilder().setId("N2K").setNamespace(
                    Namespace.newBuilder().setId("v").setName("virtru.com").setFqn("https://virtru.com").build())
                    .setName("Need to Know").setRule(AttributeRuleTypeEnum.ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF).setFqn(fqn.toString()).build();
        }
        else if (key.equals(REL.getKey())) {
            return Attribute.newBuilder().setId("REL").setNamespace(
                    Namespace.newBuilder().setId("v").setName("virtru.com").setFqn("https://virtru.com").build())
                    .setName("Releasable To").setRule(AttributeRuleTypeEnum.ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF).setFqn(fqn.toString()).build();
        }
        else {
            return null;
        }
    }

    private Value mockValueFor(Autoconfigure.AttributeValueFQN fqn) throws AutoConfigureException {
        Autoconfigure.AttributeNameFQN an = fqn.prefix();
        System.out.println(an);
        Attribute a = mockAttributeFor(an);
        System.out.println(a);
        String v = fqn.value();
        Value p = Value.newBuilder()
        .setId(a.getId() + ":" + v)
        .setAttribute(a)
        .setValue(v)
        .setFqn(fqn.toString())
        .build();

        if (an.getKey().equals(N2K.getKey())){
            switch (v.toUpperCase()) {
                case "INT":
                    p = p.toBuilder().addGrants(KeyAccessServer.newBuilder().setUri(KAS_UK).build()).build();
                    break;
                case "HCS":
                    p = p.toBuilder().addGrants(KeyAccessServer.newBuilder().setUri(KAS_US_HCS).build()).build();
                    break;
                case "SI":
                    p = p.toBuilder().addGrants(KeyAccessServer.newBuilder().setUri(KAS_US_SA).build()).build();
                    break;
            }
        }
        else if (an.getKey().equals(REL.getKey())) {
                switch (v.toUpperCase()) {
                    case "FVEY":
                        p = p.toBuilder().addGrants(KeyAccessServer.newBuilder().setUri(KAS_AU).build())
                        .addGrants(1, KeyAccessServer.newBuilder().setUri(KAS_CA).build())
                        .addGrants(1, KeyAccessServer.newBuilder().setUri(KAS_UK).build())
                        .addGrants(1, KeyAccessServer.newBuilder().setUri(KAS_NZ).build())
                        .addGrants(1, KeyAccessServer.newBuilder().setUri(KAS_US).build())
                        .build();
                        break;
                    case "AUS":
                        p = p.toBuilder().addGrants(KeyAccessServer.newBuilder().setUri(KAS_AU).build())
                        .build();
                        break;
                    case "CAN":
                        p = p.toBuilder().addGrants(0, KeyAccessServer.newBuilder().setUri(KAS_CA).build())
                        .build();
                        break;
                    case "GBR":
                        p = p.toBuilder().addGrants(KeyAccessServer.newBuilder().setUri(KAS_UK).build())
                        .build();
                        break;
                    case "NZL":
                        p = p.toBuilder().addGrants(KeyAccessServer.newBuilder().setUri(KAS_NZ).build())
                        .build();
                        break;
                    case "USA":
                        p = p.toBuilder().addGrants(KeyAccessServer.newBuilder().setUri(KAS_US).build())
                        .build();
                        break;
                }
        }
        else if (an.getKey().equals(CLS.getKey())){
            // defaults only
        }
        return p;
    }

    @Test
    public void testAttributeFromURL() throws AutoConfigureException {
        for (TestCase tc : List.of(
            new TestCase("letter", "http://e/attr/a", "http://e", "a"),
            new TestCase("number", "http://e/attr/1", "http://e", "1"),
            new TestCase("emoji", "http://e/attr/%F0%9F%98%81", "http://e", "😁"),
            new TestCase("dash", "http://a-b.com/attr/b-c", "http://a-b.com", "b-c")
        )) {
            Autoconfigure.AttributeNameFQN a = new Autoconfigure.AttributeNameFQN(tc.getU());
            assertThat(a.authority()).isEqualTo(tc.getAuth());
            assertThat(a.name()).isEqualTo(tc.getName());
        }
    }

    @Test
    public void testAttributeFromMalformedURL() {
        for (TestCase tc : List.of(
            new TestCase("no name", "http://e/attr"),
            new TestCase("invalid prefix 1", "hxxp://e/attr/a"),
            new TestCase("invalid prefix 2", "e/attr/a"),
            new TestCase("invalid prefix 3", "file://e/attr/a"),
            new TestCase("invalid prefix 4", "http:///attr/a"),
            new TestCase("bad encoding", "https://a/attr/%😁"),
            new TestCase("with value", "http://e/attr/a/value/b")
        )) {
            assertThatThrownBy(() -> new Autoconfigure.AttributeNameFQN(tc.getU()))
                .isInstanceOf(AutoConfigureException.class);
        }
    }

    @Test
    public void testAttributeValueFromURL() {
        List<TestCase> testCases = List.of(
            new TestCase("number", "http://e/attr/a/value/1", "http://e", "a", "1"),
            new TestCase("space", "http://e/attr/a/value/%20", "http://e", "a", " "),
            new TestCase("emoji", "http://e/attr/a/value/%F0%9F%98%81", "http://e", "a", "😁"),
            new TestCase("numberdef", "http://e/attr/1/value/one", "http://e", "1", "one"),
            new TestCase("valuevalue", "http://e/attr/value/value/one", "http://e", "value", "one"),
            new TestCase("dash", "http://a-b.com/attr/b-c/value/c-d", "http://a-b.com", "b-c", "c-d")
        );

        for (TestCase tc : testCases) {
            assertDoesNotThrow(() -> {
                AttributeValueFQN a = new AttributeValueFQN(tc.getU());
                assertThat(a.authority()).isEqualTo(tc.getAuth());
                assertThat(a.name()).isEqualTo(tc.getName());
                assertThat(a.value()).isEqualTo(tc.getValue());
            });
        }
    }

    @Test
    public void testAttributeValueFromMalformedURL() {
        List<TestCase> testCases = List.of(
            new TestCase("no name", "http://e/attr/value/1"),
            new TestCase("no value", "http://e/attr/who/value"),
            new TestCase("invalid prefix 1", "hxxp://e/attr/a/value/1"),
            new TestCase("invalid prefix 2", "e/attr/a/a/value/1"),
            new TestCase("bad encoding", "https://a/attr/emoji/value/%😁")
        );

        for (TestCase tc : testCases) {
            assertThatThrownBy(() -> new AttributeValueFQN(tc.getU()))
                .isInstanceOf(AutoConfigureException.class)
                .hasMessageContaining("invalid type");
        }
    }

    @Test
    public void testConfigurationServicePutGet() {
        List<ConfigurationTestCase> testCases = List.of(
            new ConfigurationTestCase("default", List.of(clsA), 1, List.of()),
            new ConfigurationTestCase("one-country", List.of(rel2gbr), 1, List.of(KAS_UK)),
            new ConfigurationTestCase("two-country", List.of(rel2gbr, rel2nzl), 2, List.of(KAS_UK, KAS_NZ)),
            new ConfigurationTestCase("with-default", List.of(clsA, rel2gbr), 2, List.of(KAS_UK)),
            new ConfigurationTestCase("need-to-know", List.of(clsTS, rel2usa, n2kSI), 3, List.of(KAS_US, KAS_US_SA))
        );

        for (ConfigurationTestCase tc : testCases) {
            System.out.println(tc.name);
            assertDoesNotThrow(() -> {
                List<Value> v = valuesToPolicy(tc.getPolicy().toArray(new AttributeValueFQN[0]));
                Granter grants = Autoconfigure.newGranterFromAttributes(v.toArray(new Value[0]));
                assertThat(grants).isNotNull();
                assertThat(grants.getGrants()).hasSize(tc.getSize());
                assertThat(policyToStringKeys(tc.getPolicy())).containsAll(grants.getGrants().keySet());
                Set<String> actualKases = new HashSet<>();
                for (Autoconfigure.KeyAccessGrant g : grants.getGrants().values()) {
                    assertThat(g).isNotNull();
                    for (String k : g.kases){
                        actualKases.add(k);
                    }
                }

                String[] kasArray = tc.getKases().toArray(new String[tc.getKases().size()]);
                assertThat(actualKases).containsExactlyInAnyOrder(kasArray);
            }
            );
        }
    }

    @Test
    public void testReasonerConstructAttributeBoolean() {
        List<ReasonerTestCase> testCases = List.of(
            new ReasonerTestCase(
                "one actual with default",
                List.of(clsS, rel2can),
                List.of(KAS_US),
                "https://virtru.com/attr/Classification/value/Secret&https://virtru.com/attr/Releasable%20To/value/CAN",
                "[DEFAULT]&(http://kas.ca/)",
                "(http://kas.ca/)",
                List.of(new SplitStep(KAS_CA, ""))
            ),
            new ReasonerTestCase(
                "one defaulted attr",
                List.of(clsS),
                List.of(KAS_US),
                "https://virtru.com/attr/Classification/value/Secret",
                "[DEFAULT]",
                "",
                List.of(new SplitStep(KAS_US, ""))
            ),
            new ReasonerTestCase(
                "empty policy",
                List.of(),
                List.of(KAS_US),
                "∅",
                "",
                "",
                List.of(new SplitStep(KAS_US, ""))
            ),
            new ReasonerTestCase(
                "old school splits",
                List.of(),
                List.of(KAS_AU, KAS_CA, KAS_US),
                "∅",
                "",
                "",
                List.of(new SplitStep(KAS_AU, "1"), new SplitStep(KAS_CA, "2"), new SplitStep(KAS_US, "3"))
            ),
            new ReasonerTestCase(
                "simple with all three ops",
                List.of(clsS, rel2gbr, n2kInt),
                List.of(KAS_US),
                "https://virtru.com/attr/Classification/value/Secret&https://virtru.com/attr/Releasable%20To/value/GBR&https://virtru.com/attr/Need%20to%20Know/value/INT",
                "[DEFAULT]&(http://kas.uk/)&(http://kas.uk/)",
                "(http://kas.uk/)",
                List.of(new SplitStep(KAS_UK, ""))
            ),
            new ReasonerTestCase(
                "compartments",
                List.of(clsS, rel2gbr, rel2usa, n2kHCS, n2kSI),
                List.of(KAS_US),
                "https://virtru.com/attr/Classification/value/Secret&https://virtru.com/attr/Releasable%20To/value/{GBR,USA}&https://virtru.com/attr/Need%20to%20Know/value/{HCS,SI}",
                "[DEFAULT]&(http://kas.uk/⋁http://kas.us/)&(http://hcs.kas.us/⋀http://si.kas.us/)",
                "(http://kas.uk/⋁http://kas.us/)&(http://hcs.kas.us/)&(http://si.kas.us/)",
                List.of(new SplitStep(KAS_UK, "1"), new SplitStep(KAS_US, "1"), new SplitStep(KAS_US_HCS, "2"), new SplitStep(KAS_US_SA, "3"))
            ),
            new ReasonerTestCase(
                "compartments - case insensitive",
                List.of(
                    messUpV(clsS), messUpV(rel2gbr), messUpV(rel2usa), messUpV(n2kHCS), messUpV(n2kSI)
                ),
                List.of(KAS_US),
                "https://virtru.com/attr/Classification/value/Secret&https://virtru.com/attr/Releasable%20To/value/{GBR,USA}&https://virtru.com/attr/Need%20to%20Know/value/{HCS,SI}",
                "[DEFAULT]&(http://kas.uk/⋁http://kas.us/)&(http://hcs.kas.us/⋀http://si.kas.us/)",
                "(http://kas.uk/⋁http://kas.us/)&(http://hcs.kas.us/)&(http://si.kas.us/)",
                List.of(new SplitStep(KAS_UK, "1"), new SplitStep(KAS_US, "1"), new SplitStep(KAS_US_HCS, "2"), new SplitStep(KAS_US_SA, "3"))
            )
        );

        for (ReasonerTestCase tc : testCases) {
            assertDoesNotThrow(() -> {
                Granter reasoner = Autoconfigure.newGranterFromAttributes(valuesToPolicy(tc.getPolicy().toArray(new AttributeValueFQN[0])).toArray(new Value[0]));
                assertThat(reasoner).isNotNull();

                AttributeBooleanExpression actualAB = reasoner.constructAttributeBoolean();
                assertThat(actualAB.toString().toLowerCase()).isEqualTo(tc.getAts().toLowerCase());

                BooleanKeyExpression actualKeyed = reasoner.insertKeysForAttribute(actualAB);
                assertThat(actualKeyed.toString()).isEqualTo(tc.getKeyed());

                String reduced = actualKeyed.reduce().toString();
                assertThat(reduced).isEqualTo(tc.getReduced());

                var wrapper = new Object(){ int i = 0; };
                List<SplitStep> plan = reasoner.plan(tc.getDefaults(), () -> {
                    return String.valueOf(wrapper.i++ + 1);
                }
                
                );
                assertThat(plan.size()).isEqualTo(tc.getPlan().size());
                assertThat(plan).isEqualTo(tc.getPlan());
            }
            );
        }
    }


    private static class TestCase {
        private final String n;
        private final String u;
        private final String auth;
        private final String name;
        private final String value;


        TestCase(String n, String u, String auth, String name, String value) {
            this.n = n;
            this.u = u;
            this.auth = auth;
            this.name = name;
            this.value = value;
        }

        TestCase(String n, String u, String auth, String name) {
            this(n, u, auth, name, null);
        }

        TestCase(String n, String u) {
            this(n, u, null, null, null);
        }

        public String getU() {
            return u;
        }

        public String getAuth() {
            return auth;
        }

        public String getName() {
            return name;
        }

        public String getValue() {
            return value;
        }

        public Autoconfigure.AttributeValueFQN getA() throws AutoConfigureException {
            return new Autoconfigure.AttributeValueFQN(u);
        }
    }

    private static class ConfigurationTestCase {
        private final String name;
        private final List<AttributeValueFQN> policy;
        private final int size;
        private final List<String> kases;

        ConfigurationTestCase(String name, List<AttributeValueFQN> policy, int size, List<String> kases) {
            this.name = name;
            this.policy = policy;
            this.size = size;
            this.kases = kases;
        }

        public String getN() {
            return name;
        }

        public List<AttributeValueFQN> getPolicy() {
            return policy;
        }

        public int getSize() {
            return size;
        }

        public List<String> getKases() {
            return kases;
        }
    }

    private static class ReasonerTestCase {
        private final String name;
        private final List<AttributeValueFQN> policy;
        private final List<String> defaults;
        private final String ats;
        private final String keyed;
        private final String reduced;
        private final List<SplitStep> plan;

        ReasonerTestCase(String name, List<AttributeValueFQN> policy, List<String> defaults, String ats, String keyed, String reduced, List<SplitStep> plan) {
            this.name = name;
            this.policy = policy;
            this.defaults = defaults;
            this.ats = ats;
            this.keyed = keyed;
            this.reduced = reduced;
            this.plan = plan;
        }

        public String getN() {
            return name;
        }

        public List<AttributeValueFQN> getPolicy() {
            return policy;
        }

        public List<String> getDefaults() {
            return defaults;
        }

        public String getAts() {
            return ats;
        }

        public String getKeyed() {
            return keyed;
        }

        public String getReduced() {
            return reduced;
        }

        public List<SplitStep> getPlan() {
            return plan;
        }
    }
}
