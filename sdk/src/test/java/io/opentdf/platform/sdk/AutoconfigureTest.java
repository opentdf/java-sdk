package io.opentdf.platform.sdk;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import io.opentdf.platform.policy.Attribute;
import io.opentdf.platform.policy.Value;
import io.opentdf.platform.policy.attributes.AttributesServiceGrpc;
import io.opentdf.platform.policy.attributes.GetAttributeValuesByFqnsRequest;
import io.opentdf.platform.policy.attributes.GetAttributeValuesByFqnsResponse;
import io.opentdf.platform.sdk.Autoconfigure.AttributeValueFQN;
import io.opentdf.platform.sdk.Autoconfigure.Granter.AttributeBooleanExpression;
import io.opentdf.platform.sdk.Autoconfigure.Granter.BooleanKeyExpression;
import io.opentdf.platform.sdk.Autoconfigure.KeySplitStep;
import io.opentdf.platform.sdk.Autoconfigure.Granter;
import io.opentdf.platform.policy.Namespace;
import io.opentdf.platform.policy.PublicKey;
import io.opentdf.platform.policy.KeyAccessServer;
import io.opentdf.platform.policy.AttributeRuleTypeEnum;
import io.opentdf.platform.policy.KasPublicKey;
import io.opentdf.platform.policy.KasPublicKeyAlgEnum;
import io.opentdf.platform.policy.KasPublicKeySet;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.google.common.util.concurrent.SettableFuture;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AutoconfigureTest {

    private static final String KAS_AU = "https://kas.au/";
    private static final String KAS_CA = "https://kas.ca/";
    private static final String KAS_UK = "https://kas.uk/";
    private static final String KAS_NZ = "https://kas.nz/";
    private static final String KAS_US = "https://kas.us/";
    private static final String KAS_US_HCS = "https://hcs.kas.us/";
    private static final String KAS_US_SA = "https://si.kas.us/";
    public static final String SPECIFIED_KAS = "https://attr.kas.com/";
    public static final String EVEN_MORE_SPECIFIC_KAS = "https://value.kas.com/";
    private static final String NAMESPACE_KAS = "https://namespace.kas.com/";
    private static Autoconfigure.AttributeNameFQN SPKSPECKED;
    private static Autoconfigure.AttributeNameFQN SPKUNSPECKED;

    private static Autoconfigure.AttributeNameFQN CLS;
    private static Autoconfigure.AttributeNameFQN N2K;
    private static Autoconfigure.AttributeNameFQN REL;
    private static Autoconfigure.AttributeNameFQN UNSPECKED;
    private static Autoconfigure.AttributeNameFQN SPECKED;

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
    private static Autoconfigure.AttributeValueFQN uns2uns;
    private static Autoconfigure.AttributeValueFQN uns2spk;
    private static Autoconfigure.AttributeValueFQN spk2uns;
    private static Autoconfigure.AttributeValueFQN spk2spk;
    private static AttributeValueFQN spk2uns2uns;
    private static AttributeValueFQN spk2uns2spk;
    private static Autoconfigure.AttributeValueFQN spk2spk2uns;
    private static Autoconfigure.AttributeValueFQN spk2spk2spk;

    @BeforeAll
    public static void setup() throws AutoConfigureException {
        // Initialize the FQNs (Fully Qualified Names)
        CLS = new Autoconfigure.AttributeNameFQN("https://virtru.com/attr/Classification");
        N2K = new Autoconfigure.AttributeNameFQN("https://virtru.com/attr/Need%20to%20Know");
        REL = new Autoconfigure.AttributeNameFQN("https://virtru.com/attr/Releasable%20To");
        UNSPECKED = new Autoconfigure.AttributeNameFQN("https://other.com/attr/unspecified");
        SPECKED = new Autoconfigure.AttributeNameFQN("https://other.com/attr/specified");
        SPKUNSPECKED = new Autoconfigure.AttributeNameFQN("https://hasgrants.com/attr/unspecified");
        SPKSPECKED = new Autoconfigure.AttributeNameFQN("https://hasgrants.com/attr/specified");

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

        uns2uns = new Autoconfigure.AttributeValueFQN("https://other.com/attr/unspecified/value/unspecked");
        uns2spk = new Autoconfigure.AttributeValueFQN("https://other.com/attr/unspecified/value/specked");
        spk2uns = new Autoconfigure.AttributeValueFQN("https://other.com/attr/specified/value/unspecked");
        spk2spk = new Autoconfigure.AttributeValueFQN("https://other.com/attr/specified/value/specked");

        spk2uns2uns = new Autoconfigure.AttributeValueFQN("https://hasgrants.com/attr/unspecified/value/unspecked");
        spk2uns2spk = new Autoconfigure.AttributeValueFQN("https://hasgrants.com/attr/unspecified/value/specked");
        spk2spk2uns = new Autoconfigure.AttributeValueFQN("https://hasgrants.com/attr/specified/value/unspecked");
        spk2spk2spk = new Autoconfigure.AttributeValueFQN("https://hasgrants.com/attr/specified/value/specked");
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
        for (AttributeValueFQN afqn : List.of(p)) {
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
        Namespace ns1 = Namespace.newBuilder().setId("v").setName("virtru.com").setFqn("https://virtru.com").build();
        Namespace ns2 = Namespace.newBuilder().setId("o").setName("other.com").setFqn("https://other.com").build();
        Namespace ns3 = Namespace.newBuilder().setId("h").setName("hasgrants.com").addGrants(KeyAccessServer.newBuilder().setUri(NAMESPACE_KAS).build()).setFqn("https://hasgrants.com").build();

        String key = fqn.getKey();
        if (key.equals(CLS.getKey())) {
            return Attribute.newBuilder().setId("CLS").setNamespace(ns1)
                    .setName("Classification").setRule(AttributeRuleTypeEnum.ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY)
                    .setFqn(fqn.toString()).build();
        } else if (key.equals(N2K.getKey())) {
            return Attribute.newBuilder().setId("N2K").setNamespace(ns1)
                    .setName("Need to Know").setRule(AttributeRuleTypeEnum.ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF)
                    .setFqn(fqn.toString()).build();
        } else if (key.equals(REL.getKey())) {
            return Attribute.newBuilder().setId("REL").setNamespace(ns1)
                    .setName("Releasable To").setRule(AttributeRuleTypeEnum.ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
                    .setFqn(fqn.toString()).build();
        } else if (key.equals(SPECKED.getKey())) {
            return Attribute.newBuilder().setId("SPK").setNamespace(ns2)
                    .setName("specified").setRule(AttributeRuleTypeEnum.ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
                    .setFqn(fqn.toString())
                    .addGrants(KeyAccessServer.newBuilder().setUri(SPECIFIED_KAS).build())
                    .build();
        } else if (key.equals(UNSPECKED.getKey())) {
            return Attribute.newBuilder().setId("UNS").setNamespace(ns2)
                    .setName("unspecified").setRule(AttributeRuleTypeEnum.ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
                    .setFqn(fqn.toString()).build();
        } else if (key.equals(SPKSPECKED.getKey())) {
            return Attribute.newBuilder().setId("SPKSPK").setNamespace(ns3)
                    .setName("specified").setRule(AttributeRuleTypeEnum.ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
                    .addGrants(KeyAccessServer.newBuilder().setUri(SPECIFIED_KAS).build())
                    .setName(fqn.toString())
                    .build();
        } else if (key.equals(SPKUNSPECKED.getKey())) {
            return Attribute.newBuilder().setId("SPKUNSPK").setNamespace(ns3)
                    .setName("unspecified").setRule(AttributeRuleTypeEnum.ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
                    .setName(fqn.toString())
                    .build();
        }

        throw new IllegalArgumentException("Key not recognized: " + key);
    }

    private Value mockValueFor(Autoconfigure.AttributeValueFQN fqn) throws AutoConfigureException {
        Autoconfigure.AttributeNameFQN an = fqn.prefix();
        Attribute a = mockAttributeFor(an);
        String v = fqn.value();
        Value p = Value.newBuilder()
                .setId(a.getId() + ":" + v)
                .setAttribute(a)
                .setValue(v)
                .setFqn(fqn.toString())
                .build();

        if (an.getKey().equals(N2K.getKey())) {
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
        } else if (an.getKey().equals(REL.getKey())) {
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
        } else if (an.getKey().equals(CLS.getKey())) {
            // defaults only
        } else if (List.of(SPECKED.getKey(), SPKSPECKED.getKey()).contains(an.getKey())) {
            if (fqn.value().equalsIgnoreCase("specked")) {
                p = p.toBuilder().addGrants(KeyAccessServer.newBuilder().setUri(EVEN_MORE_SPECIFIC_KAS).build())
                        .build();
            }
        } else if (List.of(UNSPECKED.getKey(), SPKUNSPECKED.getKey()).contains(an.getKey())) {
            if (fqn.value().equalsIgnoreCase("specked")) {
                p = p.toBuilder().addGrants(KeyAccessServer.newBuilder().setUri(EVEN_MORE_SPECIFIC_KAS).build())
                        .build();
            }
        }
        return p;
    }

    @Test
    public void testAttributeFromURL() throws AutoConfigureException {
        for (TestCase tc : List.of(
                new TestCase("letter", "https://e/attr/a", "https://e", "a"),
                new TestCase("number", "https://e/attr/1", "https://e", "1"),
                new TestCase("emoji", "https://e/attr/%F0%9F%98%81", "https://e", "😁"),
                new TestCase("dash", "https://a-b.com/attr/b-c", "https://a-b.com", "b-c"))) {
            Autoconfigure.AttributeNameFQN a = new Autoconfigure.AttributeNameFQN(tc.getU());
            assertThat(a.authority()).isEqualTo(tc.getAuth());
            assertThat(a.name()).isEqualTo(tc.getName());
        }
    }

    @Test
    public void testAttributeFromMalformedURL() {
        for (TestCase tc : List.of(
                new TestCase("no name", "https://e/attr"),
                new TestCase("invalid prefix 1", "hxxp://e/attr/a"),
                new TestCase("invalid prefix 2", "e/attr/a"),
                new TestCase("invalid prefix 3", "file://e/attr/a"),
                new TestCase("invalid prefix 4", "https:///attr/a"),
                new TestCase("bad encoding", "https://a/attr/%😁"),
                new TestCase("with value", "https://e/attr/a/value/b"))) {
            assertThatThrownBy(() -> new Autoconfigure.AttributeNameFQN(tc.getU()))
                    .isInstanceOf(AutoConfigureException.class);
        }
    }

    @Test
    public void testAttributeValueFromURL() {
        List<TestCase> testCases = List.of(
                new TestCase("number", "https://e/attr/a/value/1", "https://e", "a", "1"),
                new TestCase("space", "https://e/attr/a/value/%20", "https://e", "a", " "),
                new TestCase("emoji", "https://e/attr/a/value/%F0%9F%98%81", "https://e", "a", "😁"),
                new TestCase("numberdef", "https://e/attr/1/value/one", "https://e", "1", "one"),
                new TestCase("valuevalue", "https://e/attr/value/value/one", "https://e", "value", "one"),
                new TestCase("dash", "https://a-b.com/attr/b-c/value/c-d", "https://a-b.com", "b-c", "c-d"));

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
                new TestCase("no name", "https://e/attr/value/1"),
                new TestCase("no value", "https://e/attr/who/value"),
                new TestCase("invalid prefix 1", "hxxp://e/attr/a/value/1"),
                new TestCase("invalid prefix 2", "e/attr/a/a/value/1"),
                new TestCase("bad encoding", "https://a/attr/emoji/value/%😁"));

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
                new ConfigurationTestCase("need-to-know", List.of(clsTS, rel2usa, n2kSI), 3,
                        List.of(KAS_US, KAS_US_SA)));

        for (ConfigurationTestCase tc : testCases) {
            assertDoesNotThrow(() -> {
                List<Value> v = valuesToPolicy(tc.getPolicy().toArray(new AttributeValueFQN[0]));
                Granter grants = Autoconfigure.newGranterFromAttributes(v.toArray(new Value[0]));
                assertThat(grants).isNotNull();
                assertThat(grants.getGrants()).hasSize(tc.getSize());
                assertThat(policyToStringKeys(tc.getPolicy())).containsAll(grants.getGrants().keySet());
                Set<String> actualKases = new HashSet<>();
                for (Autoconfigure.KeyAccessGrant g : grants.getGrants().values()) {
                    assertThat(g).isNotNull();
                    for (String k : g.kases) {
                        actualKases.add(k);
                    }
                }

                String[] kasArray = tc.getKases().toArray(new String[tc.getKases().size()]);
                assertThat(actualKases).containsExactlyInAnyOrder(kasArray);
            });
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
                        "[DEFAULT]&(https://kas.ca/)",
                        "(https://kas.ca/)",
                        List.of(new KeySplitStep(KAS_CA, ""))),
                new ReasonerTestCase(
                        "one defaulted attr",
                        List.of(clsS),
                        List.of(KAS_US),
                        "https://virtru.com/attr/Classification/value/Secret",
                        "[DEFAULT]",
                        "",
                        List.of(new KeySplitStep(KAS_US, ""))),
                new ReasonerTestCase(
                        "empty policy",
                        List.of(),
                        List.of(KAS_US),
                        "∅",
                        "",
                        "",
                        List.of(new KeySplitStep(KAS_US, ""))),
                new ReasonerTestCase(
                        "old school splits",
                        List.of(),
                        List.of(KAS_AU, KAS_CA, KAS_US),
                        "∅",
                        "",
                        "",
                        List.of(new KeySplitStep(KAS_AU, "1"), new KeySplitStep(KAS_CA, "2"),
                                new KeySplitStep(KAS_US, "3"))),
                new ReasonerTestCase(
                        "simple with all three ops",
                        List.of(clsS, rel2gbr, n2kInt),
                        List.of(KAS_US),
                        "https://virtru.com/attr/Classification/value/Secret&https://virtru.com/attr/Releasable%20To/value/GBR&https://virtru.com/attr/Need%20to%20Know/value/INT",
                        "[DEFAULT]&(https://kas.uk/)&(https://kas.uk/)",
                        "(https://kas.uk/)",
                        List.of(new KeySplitStep(KAS_UK, ""))),
                new ReasonerTestCase(
                        "compartments",
                        List.of(clsS, rel2gbr, rel2usa, n2kHCS, n2kSI),
                        List.of(KAS_US),
                        "https://virtru.com/attr/Classification/value/Secret&https://virtru.com/attr/Releasable%20To/value/{GBR,USA}&https://virtru.com/attr/Need%20to%20Know/value/{HCS,SI}",
                        "[DEFAULT]&(https://kas.uk/⋁https://kas.us/)&(https://hcs.kas.us/⋀https://si.kas.us/)",
                        "(https://kas.uk/⋁https://kas.us/)&(https://hcs.kas.us/)&(https://si.kas.us/)",
                        List.of(new KeySplitStep(KAS_UK, "1"), new KeySplitStep(KAS_US, "1"),
                                new KeySplitStep(KAS_US_HCS, "2"), new KeySplitStep(KAS_US_SA, "3"))),
                new ReasonerTestCase(
                        "compartments - case insensitive",
                        List.of(
                                messUpV(clsS), messUpV(rel2gbr), messUpV(rel2usa), messUpV(n2kHCS), messUpV(n2kSI)),
                        List.of(KAS_US),
                        "https://virtru.com/attr/Classification/value/Secret&https://virtru.com/attr/Releasable%20To/value/{GBR,USA}&https://virtru.com/attr/Need%20to%20Know/value/{HCS,SI}",
                        "[DEFAULT]&(https://kas.uk/⋁https://kas.us/)&(https://hcs.kas.us/⋀https://si.kas.us/)",
                        "(https://kas.uk/⋁https://kas.us/)&(https://hcs.kas.us/)&(https://si.kas.us/)",
                        List.of(new KeySplitStep(KAS_UK, "1"), new KeySplitStep(KAS_US, "1"),
                                new KeySplitStep(KAS_US_HCS, "2"), new KeySplitStep(KAS_US_SA, "3"))));

        for (ReasonerTestCase tc : testCases) {
            Granter reasoner = Autoconfigure.newGranterFromAttributes(
                    valuesToPolicy(tc.getPolicy().toArray(new AttributeValueFQN[0])).toArray(new Value[0]));
            assertThat(reasoner).isNotNull();

            AttributeBooleanExpression actualAB = reasoner.constructAttributeBoolean();
            assertThat(actualAB.toString().toLowerCase()).isEqualTo(tc.getAts().toLowerCase());

            BooleanKeyExpression actualKeyed = reasoner.insertKeysForAttribute(actualAB);
            assertThat(actualKeyed.toString()).isEqualTo(tc.getKeyed());

            String reduced = actualKeyed.reduce().toString();
            assertThat(reduced).isEqualTo(tc.getReduced());

            var wrapper = new Object() {
                int i = 0;
            };
            List<KeySplitStep> plan = reasoner.plan(tc.getDefaults(), () -> {
                        return String.valueOf(wrapper.i++ + 1);
                    }

            );
            assertThat(plan).isEqualTo(tc.getPlan());
        }
    }

    GetAttributeValuesByFqnsResponse getResponse(GetAttributeValuesByFqnsRequest req) {
        GetAttributeValuesByFqnsResponse.Builder builder = GetAttributeValuesByFqnsResponse.newBuilder();

        for (String v : req.getFqnsList()) {
            AttributeValueFQN vfqn;
            try {
                vfqn = new AttributeValueFQN(v);
            } catch (Exception e) {
                return null; // Or throw the exception as needed
            }

            Value val = mockValueFor(vfqn);

            builder.putFqnAttributeValues(v, GetAttributeValuesByFqnsResponse.AttributeAndValue.newBuilder()
                    .setAttribute(val.getAttribute())
                    .setValue(val)
                    .build());
        }

        return builder.build();
    }

    @Test
    public void testReasonerSpecificity() {
        List<ReasonerTestCase> testCases = List.of(
                new ReasonerTestCase(
                        "uns.uns => default",
                        List.of(uns2uns),
                        List.of(KAS_US),
                        List.of(new KeySplitStep(KAS_US, ""))),
                new ReasonerTestCase(
                        "uns.spk => spk",
                        List.of(uns2spk),
                        List.of(KAS_US),
                        List.of(new KeySplitStep(EVEN_MORE_SPECIFIC_KAS, ""))),
                new ReasonerTestCase(
                        "spk.uns => spk",
                        List.of(spk2uns),
                        List.of(KAS_US),
                        List.of(new KeySplitStep(SPECIFIED_KAS, ""))),
                new ReasonerTestCase(
                        "spk.spk => value.spk",
                        List.of(spk2spk),
                        List.of(KAS_US),
                        List.of(new KeySplitStep(EVEN_MORE_SPECIFIC_KAS, ""))),
                new ReasonerTestCase(
                        "spk.spk & spk.uns => value.spk || attr.spk",
                        List.of(spk2spk, spk2uns),
                        List.of(KAS_US),
                        List.of(new KeySplitStep(EVEN_MORE_SPECIFIC_KAS, "1"), new KeySplitStep(SPECIFIED_KAS, "1"))),
                new ReasonerTestCase(
                        "spk.uns & spk.spk => value.spk || attr.spk",
                        List.of(spk2uns, spk2spk),
                        List.of(KAS_US),
                        List.of(new KeySplitStep(SPECIFIED_KAS, "1"), new KeySplitStep(EVEN_MORE_SPECIFIC_KAS, "1"))),
                new ReasonerTestCase(
                        "uns.spk & spk.spk => value.spk",
                        List.of(spk2spk, uns2spk),
                        List.of(KAS_US),
                        List.of(new KeySplitStep(EVEN_MORE_SPECIFIC_KAS, ""))),
                new ReasonerTestCase(
                        "uns.spk & uns.uns => spk",
                        List.of(uns2spk, uns2uns),
                        List.of(KAS_US),
                        List.of(new KeySplitStep(EVEN_MORE_SPECIFIC_KAS, ""))),
                new ReasonerTestCase(
                        "uns.uns & uns.spk => spk",
                        List.of(uns2uns, uns2spk),
                        List.of(KAS_US),
                        List.of(new KeySplitStep(EVEN_MORE_SPECIFIC_KAS, ""))),
                new ReasonerTestCase(
                        "uns.uns & uns.spk => spk",
                        List.of(uns2uns, spk2spk),
                        List.of(KAS_US),
                        List.of(new KeySplitStep(EVEN_MORE_SPECIFIC_KAS, ""))),
                new ReasonerTestCase(
                        "spk.uns.uns => ns.spk",
                        List.of(spk2uns2uns, uns2uns),
                        List.of(KAS_US),
                        List.of(new KeySplitStep(NAMESPACE_KAS, ""))),
                new ReasonerTestCase(
                        "spk.uns.uns & uns.uns => ns.spk",
                        List.of(spk2uns2uns, uns2uns),
                        List.of(KAS_US),
                        List.of(new KeySplitStep(NAMESPACE_KAS, ""))),
                new ReasonerTestCase(
                        "spk.uns.uns & uns.spk => ns.spk && spk",
                        List.of(spk2uns2uns, uns2spk),
                        List.of(KAS_US),
                        List.of(new KeySplitStep(NAMESPACE_KAS, "1"), new KeySplitStep(EVEN_MORE_SPECIFIC_KAS, "2"))),
                new ReasonerTestCase(
                        "spk.uns.uns & spk.spk.uns && spk.uns.spk => ns.spk || attr.spk || value.spk",
                        List.of(spk2uns2uns, spk2spk2uns, spk2uns2spk),
                        List.of(KAS_US),
                        List.of(new KeySplitStep(NAMESPACE_KAS, "1"), new KeySplitStep(EVEN_MORE_SPECIFIC_KAS, "1"), new KeySplitStep(SPECIFIED_KAS, "2")))
        );

        for (ReasonerTestCase tc : testCases) {
            assertDoesNotThrow(() -> {
                AttributesServiceGrpc.AttributesServiceFutureStub attributeGrpcStub = mock(
                        AttributesServiceGrpc.AttributesServiceFutureStub.class);
                lenient().when(attributeGrpcStub.getAttributeValuesByFqns(any(GetAttributeValuesByFqnsRequest.class)))
                        .thenAnswer(
                                invocation -> {
                                    GetAttributeValuesByFqnsResponse resp = getResponse(
                                            (GetAttributeValuesByFqnsRequest) invocation.getArguments()[0]);
                                    SettableFuture<GetAttributeValuesByFqnsResponse> future = SettableFuture.create();
                                    future.set(resp); // Set the request as the future's result
                                    return future;
                                });

                Granter reasoner = Autoconfigure.newGranterFromService(attributeGrpcStub, new KASKeyCache(),
                        tc.getPolicy().toArray(new AttributeValueFQN[0]));
                assertThat(reasoner).isNotNull();

                var wrapper = new Object() {
                    int i = 0;
                };
                List<KeySplitStep> plan = reasoner.plan(tc.getDefaults(), () -> {
                    return String.valueOf(wrapper.i++ + 1);
                }

                );
                assertThat(plan).hasSameElementsAs(tc.getPlan());
            });
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
        private final List<KeySplitStep> plan;

        ReasonerTestCase(String name, List<AttributeValueFQN> policy, List<String> defaults, String ats, String keyed,
                String reduced, List<KeySplitStep> plan) {
            this.name = name;
            this.policy = policy;
            this.defaults = defaults;
            this.ats = ats;
            this.keyed = keyed;
            this.reduced = reduced;
            this.plan = plan;
        }

        ReasonerTestCase(String name, List<AttributeValueFQN> policy, List<String> defaults, List<KeySplitStep> plan) {
            this.name = name;
            this.policy = policy;
            this.defaults = defaults;
            this.plan = plan;
            this.ats = null;
            this.keyed = null;
            this.reduced = null;
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

        public List<KeySplitStep> getPlan() {
            return plan;
        }
    }

    @Test
    void testStoreKeysToCache_NoKeys() {
        KASKeyCache keyCache = Mockito.mock(KASKeyCache.class);
        KeyAccessServer kas1 = KeyAccessServer.newBuilder().setPublicKey(
                PublicKey.newBuilder().setCached(
                        KasPublicKeySet.newBuilder()))
                .build();

        List<KeyAccessServer> kases = List.of(kas1);

        Autoconfigure.storeKeysToCache(kases, keyCache);

        verify(keyCache, never()).store(any(Config.KASInfo.class));
    }

    @Test
    void testStoreKeysToCache_WithKeys() {
        // Create a real KASKeyCache instance instead of mocking it
        KASKeyCache keyCache = new KASKeyCache();

        // Create the KasPublicKey object
        KasPublicKey kasPublicKey1 = KasPublicKey.newBuilder()
                .setAlg(KasPublicKeyAlgEnum.KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1)
                .setKid("test-kid")
                .setPem("public-key-pem")
                .build();

        // Add the KasPublicKey to a list
        List<KasPublicKey> kasPublicKeys = new ArrayList<>();
        kasPublicKeys.add(kasPublicKey1);

        // Create the KeyAccessServer object
        KeyAccessServer kas1 = KeyAccessServer.newBuilder()
                .setPublicKey(PublicKey.newBuilder()
                        .setCached(KasPublicKeySet.newBuilder()
                                .addAllKeys(kasPublicKeys)
                                .build()))
                .setUri("https://example.com/kas")
                .build();

        // Add the KeyAccessServer to a list
        List<KeyAccessServer> kases = List.of(kas1);

        // Call the method under test
        Autoconfigure.storeKeysToCache(kases, keyCache);

        // Verify that the key was stored in the cache
        Config.KASInfo storedKASInfo = keyCache.get("https://example.com/kas", "ec:secp256r1");
        assertNotNull(storedKASInfo);
        assertEquals("https://example.com/kas", storedKASInfo.URL);
        assertEquals("test-kid", storedKASInfo.KID);
        assertEquals("ec:secp256r1", storedKASInfo.Algorithm);
        assertEquals("public-key-pem", storedKASInfo.PublicKey);
    }

    @Test
    void testStoreKeysToCache_MultipleKasEntries() {
        // Create a real KASKeyCache instance instead of mocking it
        KASKeyCache keyCache = new KASKeyCache();

        // Create the KasPublicKey object
        KasPublicKey kasPublicKey1 = KasPublicKey.newBuilder()
                .setAlg(KasPublicKeyAlgEnum.KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1)
                .setKid("test-kid")
                .setPem("public-key-pem")
                .build();
        KasPublicKey kasPublicKey2 = KasPublicKey.newBuilder()
                .setAlg(KasPublicKeyAlgEnum.KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048)
                .setKid("test-kid-2")
                .setPem("public-key-pem-2")
                .build();

        // Add the KasPublicKey to a list
        List<KasPublicKey> kasPublicKeys = new ArrayList<>();
        kasPublicKeys.add(kasPublicKey1);
        kasPublicKeys.add(kasPublicKey2);

        // Create the KeyAccessServer object
        KeyAccessServer kas1 = KeyAccessServer.newBuilder()
                .setPublicKey(PublicKey.newBuilder()
                        .setCached(KasPublicKeySet.newBuilder()
                                .addAllKeys(kasPublicKeys)
                                .build()))
                .setUri("https://example.com/kas")
                .build();

        // Add the KeyAccessServer to a list
        List<KeyAccessServer> kases = List.of(kas1);

        // Call the method under test
        Autoconfigure.storeKeysToCache(kases, keyCache);

        // Verify that the key was stored in the cache
        Config.KASInfo storedKASInfo = keyCache.get("https://example.com/kas", "ec:secp256r1");
        assertNotNull(storedKASInfo);
        assertEquals("https://example.com/kas", storedKASInfo.URL);
        assertEquals("test-kid", storedKASInfo.KID);
        assertEquals("ec:secp256r1", storedKASInfo.Algorithm);
        assertEquals("public-key-pem", storedKASInfo.PublicKey);

        Config.KASInfo storedKASInfo2 = keyCache.get("https://example.com/kas", "rsa:2048");
        assertNotNull(storedKASInfo2);
        assertEquals("https://example.com/kas", storedKASInfo2.URL);
        assertEquals("test-kid-2", storedKASInfo2.KID);
        assertEquals("rsa:2048", storedKASInfo2.Algorithm);
        assertEquals("public-key-pem-2", storedKASInfo2.PublicKey);
    }

    GetAttributeValuesByFqnsResponse getResponseWithGrants(GetAttributeValuesByFqnsRequest req,
            List<KeyAccessServer> grants) {
        GetAttributeValuesByFqnsResponse.Builder builder = GetAttributeValuesByFqnsResponse.newBuilder();

        for (String v : req.getFqnsList()) {
            AttributeValueFQN vfqn;
            try {
                vfqn = new AttributeValueFQN(v);
            } catch (Exception e) {
                return null; // Or throw the exception as needed
            }

            Value val = Value.newBuilder(mockValueFor(vfqn)).addAllGrants(grants).build();

            builder.putFqnAttributeValues(v, GetAttributeValuesByFqnsResponse.AttributeAndValue.newBuilder()
                    .setAttribute(val.getAttribute())
                    .setValue(val)
                    .build());
        }

        return builder.build();
    }

    @Test
    void testKeyCacheFromGrants() throws InterruptedException, ExecutionException {
        // Create the KasPublicKey object
        KasPublicKey kasPublicKey1 = KasPublicKey.newBuilder()
                .setAlg(KasPublicKeyAlgEnum.KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1)
                .setKid("test-kid")
                .setPem("public-key-pem")
                .build();
        KasPublicKey kasPublicKey2 = KasPublicKey.newBuilder()
                .setAlg(KasPublicKeyAlgEnum.KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048)
                .setKid("test-kid-2")
                .setPem("public-key-pem-2")
                .build();

        // Add the KasPublicKey to a list
        List<KasPublicKey> kasPublicKeys = new ArrayList<>();
        kasPublicKeys.add(kasPublicKey1);
        kasPublicKeys.add(kasPublicKey2);

        // Create the KeyAccessServer object
        KeyAccessServer kas1 = KeyAccessServer.newBuilder()
                .setPublicKey(PublicKey.newBuilder()
                        .setCached(KasPublicKeySet.newBuilder()
                                .addAllKeys(kasPublicKeys)
                                .build()))
                .setUri("https://example.com/kas")
                .build();

        AttributesServiceGrpc.AttributesServiceFutureStub attributeGrpcStub = mock(
                AttributesServiceGrpc.AttributesServiceFutureStub.class);
        lenient().when(attributeGrpcStub.getAttributeValuesByFqns(any(GetAttributeValuesByFqnsRequest.class)))
                .thenAnswer(
                        invocation -> {
                            GetAttributeValuesByFqnsResponse resp = getResponseWithGrants(
                                    (GetAttributeValuesByFqnsRequest) invocation.getArguments()[0], List.of(kas1));
                            SettableFuture<GetAttributeValuesByFqnsResponse> future = SettableFuture.create();
                            future.set(resp); // Set the request as the future's result
                            return future;
                        });

        KASKeyCache keyCache = new KASKeyCache();

        Granter reasoner = Autoconfigure.newGranterFromService(attributeGrpcStub, keyCache,
                List.of(clsS, rel2gbr, rel2usa, n2kHCS, n2kSI).toArray(new AttributeValueFQN[0]));
        assertThat(reasoner).isNotNull();

        // Verify that the key was stored in the cache
        Config.KASInfo storedKASInfo = keyCache.get("https://example.com/kas", "ec:secp256r1");
        assertNotNull(storedKASInfo);
        assertEquals("https://example.com/kas", storedKASInfo.URL);
        assertEquals("test-kid", storedKASInfo.KID);
        assertEquals("ec:secp256r1", storedKASInfo.Algorithm);
        assertEquals("public-key-pem", storedKASInfo.PublicKey);

        Config.KASInfo storedKASInfo2 = keyCache.get("https://example.com/kas", "rsa:2048");
        assertNotNull(storedKASInfo2);
        assertEquals("https://example.com/kas", storedKASInfo2.URL);
        assertEquals("test-kid-2", storedKASInfo2.KID);
        assertEquals("rsa:2048", storedKASInfo2.Algorithm);
        assertEquals("public-key-pem-2", storedKASInfo2.PublicKey);

    }

}
