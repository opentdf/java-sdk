package io.opentdf.platform.sdk;

import com.google.gson.JsonParser;
import com.google.protobuf.ListValue;
import com.google.protobuf.NullValue;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import io.opentdf.platform.policy.Algorithm;
import io.opentdf.platform.policy.Attribute;
import io.opentdf.platform.policy.AttributeRuleTypeEnum;
import io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse;
import io.opentdf.platform.wellknownconfiguration.WellKnownServiceClientInterface;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PlannerTest {

    @ParameterizedTest
    @CsvSource({
            "rsa:2048, ALGORITHM_RSA_2048",
            "rsa:4096, ALGORITHM_RSA_4096",
            "ec:secp256r1, ALGORITHM_EC_P256",
            "ec:secp384r1, ALGORITHM_EC_P384",
            "ec:secp521r1, ALGORITHM_EC_P521",
            "hpqt:xwing, ALGORITHM_HPQT_XWING",
            "hpqt:secp256r1-mlkem768, ALGORITHM_HPQT_SECP256R1_MLKEM768",
            "hpqt:secp384r1-mlkem1024, ALGORITHM_HPQT_SECP384R1_MLKEM1024",
            "mlkem:768, ALGORITHM_MLKEM_768",
            "mlkem:1024, ALGORITHM_MLKEM_1024"
    })
    void fetchBaseKeyFromStructuredConfiguration(String wireAlgorithm, Algorithm expectedAlgorithm) {
        var wellknownService = wellknownService(baseKeyConfiguration(structuredBaseKey(wireAlgorithm)));

        var baseKey = Planner.fetchBaseKey(wellknownService);

        assertThat(baseKey).isPresent();
        var simpleKasKey = baseKey.get();
        assertThat(simpleKasKey.getKasUri()).isEqualTo("https://example.com/base_key");
        assertThat(simpleKasKey.getPublicKey().getAlgorithm()).isEqualTo(expectedAlgorithm);
        assertThat(simpleKasKey.getPublicKey().getKid()).isEqualTo("thekid");
        assertThat(simpleKasKey.getPublicKey().getPem()).isEqualTo("thepem");
    }

    @ParameterizedTest
    @ValueSource(strings = {"kas_uri", "kas_url"})
    void fetchBaseKeyFromLegacyJsonString(String kasUriField) {
        var configuration = legacyBaseKeyConfiguration(legacyBaseKeyJson(kasUriField));

        var baseKey = Planner.fetchBaseKey(wellknownService(configuration));

        assertThat(baseKey).isPresent();
        assertThat(baseKey.get().getKasUri()).isEqualTo("https://example.com/base_key");
        assertThat(baseKey.get().getPublicKey().getAlgorithm()).isEqualTo(Algorithm.ALGORITHM_RSA_2048);
        assertThat(baseKey.get().getPublicKey().getKid()).isEqualTo("thekid");
        assertThat(baseKey.get().getPublicKey().getPem()).isEqualTo("thepem");
    }

    @ParameterizedTest
    @CsvSource({
            "kas_uri, 123", "kas_uri, true",
            "kas_url, 123", "kas_url, true",
            "public_key.algorithm, 123", "public_key.algorithm, true",
            "public_key.kid, 123", "public_key.kid, true",
            "public_key.pem, 123", "public_key.pem, true"
    })
    void fetchBaseKeyRejectsNonStringLegacyField(String field, String jsonValue) {
        var configuration = legacyBaseKeyConfiguration(legacyBaseKeyWithField(field, jsonValue));

        assertThat(Planner.fetchBaseKey(wellknownService(configuration))).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "null", "{}", "{\"public_key\":null}"})
    void fetchBaseKeyWithEmptyLegacyConfiguration(String json) {
        assertThat(Planner.fetchBaseKey(wellknownService(legacyBaseKeyConfiguration(json)))).isEmpty();
    }

    @Test
    void fetchBaseKeyPreservesLegacyAliasOrder() {
        var json = "{\"kas_uri\":\"https://first.example.com/kas\","
                + "\"kas_url\":\"https://second.example.com/kas\","
                + legacyBaseKeyJson("kas_uri").substring(1);

        var baseKey = Planner.fetchBaseKey(wellknownService(legacyBaseKeyConfiguration(json)));

        assertThat(baseKey).isPresent();
        assertThat(baseKey.get().getKasUri()).isEqualTo("https://example.com/base_key");
    }

    @ParameterizedTest
    @ValueSource(strings = {"123", "true", "[]", "\"base-key\""})
    void fetchBaseKeyWithNonObjectLegacyRootStillThrows(String json) {
        var service = wellknownService(legacyBaseKeyConfiguration(json));

        assertThatThrownBy(() -> Planner.fetchBaseKey(service))
                .isInstanceOf(SDKException.class)
                .hasMessageContaining("malformed");
    }

    @ParameterizedTest
    @ValueSource(strings = {"123", "true", "[]", "\"public-key\""})
    void fetchBaseKeyWithNonObjectLegacyPublicKeyStillThrows(String jsonValue) {
        var configuration = legacyBaseKeyConfiguration(legacyBaseKeyWithField("public_key", jsonValue));
        var service = wellknownService(configuration);

        assertThatThrownBy(() -> Planner.fetchBaseKey(service))
                .isInstanceOf(SDKException.class)
                .hasMessageContaining("malformed");
    }

    @ParameterizedTest
    @CsvSource({
            "kas_uri, {}", "kas_url, []", "public_key.algorithm, {}",
            "public_key.kid, []", "public_key.pem, {}"
    })
    void fetchBaseKeyWithStructuredLegacyStringFieldStillThrows(String field, String jsonValue) {
        var configuration = legacyBaseKeyConfiguration(legacyBaseKeyWithField(field, jsonValue));
        var service = wellknownService(configuration);

        assertThatThrownBy(() -> Planner.fetchBaseKey(service))
                .isInstanceOf(SDKException.class)
                .hasMessageContaining("malformed");
    }

    @Test
    void fetchBaseKeyWithInvalidLegacyPrimitiveDoesNotHideMalformedPublicKey() {
        var configuration = legacyBaseKeyConfiguration("{\"kas_uri\":123,\"public_key\":[]}");
        var service = wellknownService(configuration);

        assertThatThrownBy(() -> Planner.fetchBaseKey(service))
                .isInstanceOf(SDKException.class)
                .hasMessageContaining("malformed");
    }

    @Test
    void fetchBaseKeyWithMalformedLegacyJsonStillThrows() {
        var configuration = Struct.newBuilder()
                .putFields("base_key", Value.newBuilder().setStringValue("{").build())
                .build();
        var service = wellknownService(configuration);

        assertThatThrownBy(() -> Planner.fetchBaseKey(service))
                .isInstanceOf(SDKException.class)
                .hasMessageContaining("malformed");
    }

    @Test
    void fetchBaseKeyWithNoBaseKey() {
        assertThat(Planner.fetchBaseKey(wellknownService(Struct.getDefaultInstance()))).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"kas_uri", "public_key", "public_key.algorithm", "public_key.kid", "public_key.pem"})
    void fetchBaseKeyWithMissingRequiredField(String field) {
        var baseKey = replaceBaseKeyField(structuredBaseKey("rsa:2048"), field, null);

        assertThat(Planner.fetchBaseKey(wellknownService(baseKeyConfiguration(baseKey)))).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"kas_uri", "public_key", "public_key.algorithm", "public_key.kid", "public_key.pem"})
    void fetchBaseKeyWithWrongRequiredFieldType(String field) {
        var baseKey = replaceBaseKeyField(structuredBaseKey("rsa:2048"), field,
                Value.newBuilder().setNumberValue(123).build());

        assertThat(Planner.fetchBaseKey(wellknownService(baseKeyConfiguration(baseKey)))).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"kas_uri", "public_key.algorithm", "public_key.kid", "public_key.pem"})
    void fetchBaseKeyWithBlankRequiredField(String field) {
        var baseKey = replaceBaseKeyField(structuredBaseKey("rsa:2048"), field,
                Value.newBuilder().setStringValue(" ").build());

        assertThat(Planner.fetchBaseKey(wellknownService(baseKeyConfiguration(baseKey)))).isEmpty();
    }

    @ParameterizedTest
    @MethodSource("invalidBaseKeyValues")
    void fetchBaseKeyWithWrongValueType(Value baseKey) {
        var configuration = Struct.newBuilder().putFields("base_key", baseKey).build();

        assertThat(Planner.fetchBaseKey(wellknownService(configuration))).isEmpty();
    }

    private static Stream<Value> invalidBaseKeyValues() {
        return Stream.of(
                Value.getDefaultInstance(),
                Value.newBuilder().setNullValue(NullValue.NULL_VALUE).build(),
                Value.newBuilder().setNumberValue(123).build(),
                Value.newBuilder().setBoolValue(true).build(),
                Value.newBuilder().setListValue(ListValue.getDefaultInstance()).build());
    }

    @ParameterizedTest
    @ValueSource(strings = {"rsa:1024", "unknown", "ALGORITHM_UNSPECIFIED", "UNRECOGNIZED"})
    void fetchBaseKeyRejectsUnsupportedAlgorithm(String algorithm) {
        var wellknownService = wellknownService(baseKeyConfiguration(structuredBaseKey(algorithm)));

        assertThat(Planner.fetchBaseKey(wellknownService)).isEmpty();
    }

    @Test
    void autoconfigureUsesFetchedBaseKeyForUnmappedAttribute() {
        var wellknownService = wellknownService(baseKeyConfiguration(structuredBaseKey("ec:secp256r1")));
        var kas = Mockito.mock(SDK.KAS.class);
        var resolvedKey = new Config.KASInfo();
        resolvedKey.URL = "https://example.com/base_key";
        resolvedKey.KID = "thekid";
        resolvedKey.Algorithm = "ec:secp256r1";
        resolvedKey.PublicKey = "thepem";
        Mockito.when(kas.getPublicKey(Mockito.any())).thenReturn(resolvedKey);
        var services = new FakeServicesBuilder().setWellknownService(wellknownService).setKas(kas).build();
        var config = configWithUnmappedAttribute();
        // A different configured default makes loss of the base key's algorithm observable.
        config.wrappingKeyType = KeyType.RSA2048Key;
        var planner = new Planner(config, services, Autoconfigure::createGranter);

        var splits = planner.getSplits();

        Assertions.assertThat(splits).containsOnlyKeys("");
        Assertions.assertThat(splits.get("")).containsExactly(resolvedKey);
        var request = ArgumentCaptor.forClass(Config.KASInfo.class);
        Mockito.verify(kas).getPublicKey(request.capture());
        assertThat(request.getValue().URL).isEqualTo("https://example.com/base_key");
        assertThat(request.getValue().KID).isEqualTo("thekid");
        assertThat(request.getValue().Algorithm).isEqualTo("ec:secp256r1");
        Mockito.verify(wellknownService).getWellKnownConfigurationBlocking(Mockito.any(), Mockito.anyMap());
    }

    @Test
    void autoconfigureFailsWithoutBaseKeyOrDefaultKasForUnmappedAttribute() {
        var kas = Mockito.mock(SDK.KAS.class);
        var services = new FakeServicesBuilder()
                .setWellknownService(wellknownService(Struct.getDefaultInstance()))
                .setKas(kas)
                .build();
        var planner = new Planner(configWithUnmappedAttribute(), services, Autoconfigure::createGranter);

        assertThatThrownBy(planner::getSplits)
                .isInstanceOf(AutoConfigureException.class)
                .hasMessage("no default KAS specified; required for grantless plans");
        Mockito.verify(kas, Mockito.never()).getPublicKey(Mockito.any());
    }

    @ParameterizedTest
    @ValueSource(strings = {"ALGORITHM_UNSPECIFIED", "UNRECOGNIZED"})
    void autoconfigureRejectsLegacyAlgorithmSentinelsBeforeDefaultKasFallback(String algorithm) {
        var json = "{\"kas_url\":\"https://example.com/base_key\","
                + "\"public_key\":{\"algorithm\":\"" + algorithm + "\",\"kid\":\"thekid\",\"pem\":\"thepem\"}}";
        var configuration = Struct.newBuilder()
                .putFields("base_key", Value.newBuilder().setStringValue(json).build())
                .build();
        var kas = Mockito.mock(SDK.KAS.class);
        var services = new FakeServicesBuilder()
                .setWellknownService(wellknownService(configuration))
                .setKas(kas)
                .build();
        var config = configWithUnmappedAttribute();
        var defaultKas = new Config.KASInfo();
        defaultKas.URL = "https://fallback.example.com/kas";
        defaultKas.Default = true;
        config.kasInfoList.add(defaultKas);
        var planner = new Planner(config, services, Autoconfigure::createGranter);

        assertThatThrownBy(planner::getSplits)
                .isInstanceOf(SDKException.class)
                .hasMessageContaining("unsupported algorithm");
        Mockito.verify(kas, Mockito.never()).getPublicKey(Mockito.any());
    }

    private static Config.TDFConfig configWithUnmappedAttribute() {
        var attribute = Attribute.newBuilder()
                .setFqn("https://example.com/attr/classification")
                .setRule(AttributeRuleTypeEnum.ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
                .build();
        var value = io.opentdf.platform.policy.Value.newBuilder()
                .setFqn("https://example.com/attr/classification/value/internal")
                .setValue("internal")
                .setAttribute(attribute)
                .build();
        var config = new Config.TDFConfig();
        config.autoconfigure = true;
        config.attributeValues = List.of(value);
        return config;
    }

    private static WellKnownServiceClientInterface wellknownService(Struct configuration) {
        var service = Mockito.mock(WellKnownServiceClientInterface.class);
        var response = GetWellKnownConfigurationResponse.newBuilder().setConfiguration(configuration).build();
        Mockito.when(service.getWellKnownConfigurationBlocking(Mockito.any(), Mockito.anyMap()))
                .thenReturn(TestUtil.successfulUnaryCall(response));
        return service;
    }

    private static Struct baseKeyConfiguration(Struct baseKey) {
        return Struct.newBuilder()
                .putFields("base_key", Value.newBuilder().setStructValue(baseKey).build())
                .build();
    }

    private static Struct legacyBaseKeyConfiguration(String json) {
        return Struct.newBuilder()
                .putFields("base_key", Value.newBuilder().setStringValue(json).build())
                .build();
    }

    private static String legacyBaseKeyJson(String kasUriField) {
        return "{\"" + kasUriField + "\":\"https://example.com/base_key\","
                + "\"public_key\":{\"algorithm\":\"ALGORITHM_RSA_2048\",\"kid\":\"thekid\",\"pem\":\"thepem\"}}";
    }

    /** Replaces one legacy JSON field with a typed value, choosing the URI alias under test. */
    private static String legacyBaseKeyWithField(String field, String jsonValue) {
        var baseKey = JsonParser.parseString(legacyBaseKeyJson("kas_url".equals(field) ? "kas_url" : "kas_uri"))
                .getAsJsonObject();
        var fields = baseKey;
        var name = field;
        if (field.startsWith("public_key.")) {
            fields = baseKey.getAsJsonObject("public_key");
            name = field.substring("public_key.".length());
        }
        fields.add(name, JsonParser.parseString(jsonValue));
        return baseKey.toString();
    }

    private static Struct structuredBaseKey(String algorithm) {
        var publicKey = Struct.newBuilder()
                .putFields("algorithm", Value.newBuilder().setStringValue(algorithm).build())
                .putFields("kid", Value.newBuilder().setStringValue("thekid").build())
                .putFields("pem", Value.newBuilder().setStringValue("thepem").build())
                .build();
        return Struct.newBuilder()
                .putFields("kas_uri", Value.newBuilder().setStringValue("https://example.com/base_key").build())
                .putFields("public_key", Value.newBuilder().setStructValue(publicKey).build())
                .build();
    }

    /** Replaces a top-level or nested public-key field; a null replacement removes the field. */
    private static Struct replaceBaseKeyField(Struct baseKey, String field, Value replacement) {
        var builder = baseKey.toBuilder();
        if (field.startsWith("public_key.")) {
            var publicKey = baseKey.getFieldsOrThrow("public_key").getStructValue().toBuilder();
            var name = field.substring("public_key.".length());
            if (replacement == null) {
                publicKey.removeFields(name);
            } else {
                publicKey.putFields(name, replacement);
            }
            builder.putFields("public_key", Value.newBuilder().setStructValue(publicKey).build());
        } else if (replacement == null) {
            builder.removeFields(field);
        } else {
            builder.putFields(field, replacement);
        }
        return builder.build();
    }

    @Test
    void generatePlanFromProvidedKases() {
        var kas1 = new Config.KASInfo();
        kas1.URL = "https://kas1.example.com";
        kas1.KID = "kid1";

        var kas2 = new Config.KASInfo();
        kas2.URL = "https://kas2.example.com";
        kas2.KID = "kid2";
        kas2.Algorithm = "ec:secp256r1";

        var tdfConfig = new Config.TDFConfig();
        tdfConfig.kasInfoList.add(kas1);
        tdfConfig.kasInfoList.add(kas2);

        var planner = new Planner(tdfConfig, new FakeServicesBuilder().build(), (ignore1, ignored2) -> { throw new IllegalArgumentException("no granter needed"); });
        List<Autoconfigure.KeySplitTemplate> splitPlan = planner.generatePlanFromProvidedKases(tdfConfig.kasInfoList);

        assertThat(splitPlan).asList().hasSize(2);
        assertThat(splitPlan.get(0).kas).isEqualTo("https://kas1.example.com");
        assertThat(splitPlan.get(0).kid).isEqualTo("kid1");
        assertThat(splitPlan.get(0).keyType).isNull();

        assertThat(splitPlan.get(1).kas).isEqualTo("https://kas2.example.com");
        assertThat(splitPlan.get(1).kid).isEqualTo("kid2");
        assertThat(splitPlan.get(1).keyType).isEqualTo(KeyType.EC256Key);

        assertThat(splitPlan.get(0).splitID).isNotEqualTo(splitPlan.get(1).splitID);
    }

    @Test
    void testFillingInKeysWithAutoConfigure() {
        var kas = Mockito.mock(SDK.KAS.class);
        Mockito.when(kas.getPublicKey(Mockito.any())).thenAnswer(invocation -> {
                Config.KASInfo kasInfo = invocation.getArgument(0, Config.KASInfo.class);
                var ret = new Config.KASInfo();
                ret.URL = kasInfo.URL;
                if (Objects.equals(kasInfo.URL, "https://kas1.example.com")) {
                    ret.PublicKey = "pem1";
                    ret.Algorithm = "rsa:2048";
                    ret.KID = "kid1";
                } else if (Objects.equals(kasInfo.URL, "https://kas2.example.com")) {
                    ret.PublicKey = "pem2";
                    ret.Algorithm = "ec:secp256r1";
                    ret.KID = "kid2";
                } else if (Objects.equals(kasInfo.URL, "https://kas3.example.com")) {
                    ret.PublicKey = "pem3";
                    ret.Algorithm = "ec:secp384r1";
                    ret.KID = "kid3";
                    assertThat(kasInfo.Algorithm).isEqualTo("ec:secp384r1");
                } else {
                    throw new IllegalArgumentException("Unexpected KAS URL: " + kasInfo.URL);
                }
                return ret;
        });
        var tdfConfig = new Config.TDFConfig();
        tdfConfig.autoconfigure = true;
        tdfConfig.wrappingKeyType = KeyType.RSA2048Key;
        tdfConfig.kasInfoList = List.of(
                new Config.KASInfo() {{
                    URL = "https://kas4.example.com";
                    KID = "kid4";
                    Algorithm = "ec:secp384r1";
                    PublicKey = "pem4";
                }}
        );
        var planner = new Planner(tdfConfig, new FakeServicesBuilder().setKas(kas).build(), (ignore1, ignored2) ->  { throw new IllegalArgumentException("no granter needed"); });
        var plan = List.of(
                new Autoconfigure.KeySplitTemplate("https://kas1.example.com", "split1", null, null),
                new Autoconfigure.KeySplitTemplate("https://kas4.example.com", "split1", "kid4", null),
                new Autoconfigure.KeySplitTemplate("https://kas2.example.com", "split2", "kid2", null),
                new Autoconfigure.KeySplitTemplate("https://kas3.example.com", "split2", null, KeyType.EC384Key)
        );
        Map<String, List<Config.KASInfo>> filledInPlan = planner.resolveKeys(plan);
        assertThat(filledInPlan.keySet().stream().collect(Collectors.toList())).asList().containsExactlyInAnyOrder("split1", "split2");
        assertThat(filledInPlan.get("split1")).asList().hasSize(2);
        var kasInfo1 = filledInPlan.get("split1").stream().filter(k -> "kid1".equals(k.KID)).findFirst().get();
        assertThat(kasInfo1.URL).isEqualTo("https://kas1.example.com");
        assertThat(kasInfo1.Algorithm).isEqualTo("rsa:2048");
        assertThat(kasInfo1.PublicKey).isEqualTo("pem1");
        var kasInfo4 = filledInPlan.get("split1").stream().filter(k -> "kid4".equals(k.KID)).findFirst().get();
        assertThat(kasInfo4.URL).isEqualTo("https://kas4.example.com");
        assertThat(kasInfo4.Algorithm).isEqualTo("ec:secp384r1");
        assertThat(kasInfo4.PublicKey).isEqualTo("pem4");

        assertThat(filledInPlan.get("split2")).asList().hasSize(2);
        var kasInfo2 = filledInPlan.get("split2").stream().filter(kasInfo -> "kid2".equals(kasInfo.KID)).findFirst().get();
        assertThat(kasInfo2.URL).isEqualTo("https://kas2.example.com");
        assertThat(kasInfo2.Algorithm).isEqualTo("ec:secp256r1");
        assertThat(kasInfo2.PublicKey).isEqualTo("pem2");
        var kasInfo3 = filledInPlan.get("split2").stream().filter(kasInfo -> "kid3".equals(kasInfo.KID)).findFirst().get();
        assertThat(kasInfo3.URL).isEqualTo("https://kas3.example.com");
        assertThat(kasInfo3.Algorithm).isEqualTo("ec:secp384r1");
        assertThat(kasInfo3.PublicKey).isEqualTo("pem3");
    }

    @Test
    void returnsOnlyDefaultKasesIfPresent() {
        var kas1 = new Config.KASInfo();
        kas1.URL = "https://kas1.example.com";
        kas1.Default = true;

        var kas2 = new Config.KASInfo();
        kas2.URL = "https://kas2.example.com";
        kas2.Default = false;

        var kas3 = new Config.KASInfo();
        kas3.URL = "https://kas3.example.com";
        kas3.Default = true;

        var config = new Config.TDFConfig();
        config.kasInfoList.addAll(List.of(kas1, kas2, kas3));

        List<String> result = Planner.defaultKases(config);

        Assertions.assertThat(result).containsExactlyInAnyOrder("https://kas1.example.com", "https://kas3.example.com");
    }

    @Test
    void returnsAllKasesIfNoDefault() {
        var kas1 = new Config.KASInfo();
        kas1.URL = "https://kas1.example.com";
        kas1.Default = false;

        var kas2 = new Config.KASInfo();
        kas2.URL = "https://kas2.example.com";
        kas2.Default = null; // not set

        var config = new Config.TDFConfig();
        config.kasInfoList.addAll(List.of(kas1, kas2));

        List<String> result = Planner.defaultKases(config);
        Assertions.assertThat(result).containsExactlyInAnyOrder("https://kas1.example.com", "https://kas2.example.com");
    }

    @Test
    void returnsEmptyListIfNoKases() {
        var config = new Config.TDFConfig();
        List<String> result = Planner.defaultKases(config);
        Assertions.assertThat(result).isEmpty();
    }

    @Test
    void usesProvidedSplitPlanWhenNotAutoconfigure() {
        var kas = Mockito.mock(SDK.KAS.class);
        Mockito.when(kas.getPublicKey(Mockito.any())).thenAnswer(invocation -> {
            Config.KASInfo kasInfo = invocation.getArgument(0, Config.KASInfo.class);
            var ret = new Config.KASInfo();
            ret.URL = kasInfo.URL;
            if (Objects.equals(kasInfo.URL, "https://kas1.example.com")) {
                ret.PublicKey = "pem1";
                ret.Algorithm = "rsa:2048";
                ret.KID = "kid1";
            } else if (Objects.equals(kasInfo.URL, "https://kas2.example.com")) {
                ret.PublicKey = "pem2";
                ret.Algorithm = "ec:secp256r1";
                ret.KID = "kid2";
            } else {
                throw new IllegalArgumentException("Unexpected KAS URL: " + kasInfo.URL);
            }
            return ret;
        });
        // Arrange
        var kas1 = new Config.KASInfo();
        kas1.URL = "https://kas1.example.com";
        kas1.KID = "kid1";
        kas1.Algorithm = "rsa:2048";

        var kas2 = new Config.KASInfo();
        kas2.URL = "https://kas2.example.com";
        kas2.KID = "kid2";
        kas2.Algorithm = "ec:secp256";

        var splitStep1 = new Autoconfigure.KeySplitStep(kas1.URL, "split1");
        var splitStep2 = new Autoconfigure.KeySplitStep(kas2.URL, "split2");

        var tdfConfig = new Config.TDFConfig();
        tdfConfig.autoconfigure = false;
        tdfConfig.kasInfoList.add(kas1);
        tdfConfig.kasInfoList.add(kas2);
        tdfConfig.splitPlan = List.of(splitStep1, splitStep2);

        var planner = new Planner(tdfConfig, new FakeServicesBuilder().setKas(kas).build(), (ignore1, ignored2) -> { throw new IllegalArgumentException("no granter needed"); });

        // Act
        Map<String, List<Config.KASInfo>> splits = planner.getSplits();

        // Assert
        Assertions.assertThat(splits).hasSize(2);
        Assertions.assertThat(splits.get("split1")).extracting("URL").containsExactly("https://kas1.example.com");
        Assertions.assertThat(splits.get("split2")).extracting("URL").containsExactly("https://kas2.example.com");
    }
}
