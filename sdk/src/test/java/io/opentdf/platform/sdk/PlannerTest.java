package io.opentdf.platform.sdk;

import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import io.opentdf.platform.policy.Algorithm;
import io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse;
import io.opentdf.platform.wellknownconfiguration.WellKnownServiceClientInterface;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

class PlannerTest {

    @Test
    void fetchBaseKey() {
        var wellknownService = Mockito.mock(WellKnownServiceClientInterface.class);
        var baseKeyJson = "{\"kas_url\":\"https://example.com/base_key\",\"public_key\":{\"algorithm\":\"ALGORITHM_RSA_2048\",\"kid\":\"thekid\",\"pem\": \"thepem\"}}";
        var val = Value.newBuilder().setStringValue(baseKeyJson).build();
        var config = Struct.newBuilder().putFields("base_key", val).build();
        var response = GetWellKnownConfigurationResponse
                .newBuilder()
                .setConfiguration(config)
                .build();

        Mockito.when(wellknownService.getWellKnownConfigurationBlocking(Mockito.any(), Mockito.anyMap()))
                .thenReturn(TestUtil.successfulUnaryCall(response));


        var baseKey = Planner.fetchBaseKey(wellknownService);
        assertThat(baseKey).isNotEmpty();
        var simpleKasKey = baseKey.get();
        assertThat(simpleKasKey.getKasUri()).isEqualTo("https://example.com/base_key");
        assertThat(simpleKasKey.getPublicKey().getAlgorithm()).isEqualTo(Algorithm.ALGORITHM_RSA_2048);
        assertThat(simpleKasKey.getPublicKey().getKid()).isEqualTo("thekid");
        assertThat(simpleKasKey.getPublicKey().getPem()).isEqualTo("thepem");
    }

    @Test
    void fetchBaseKeyWithNoBaseKey() {
        var wellknownService = Mockito.mock(WellKnownServiceClientInterface.class);
        var response = GetWellKnownConfigurationResponse
                .newBuilder()
                .setConfiguration(Struct.newBuilder().build())
                .build();

        Mockito.when(wellknownService.getWellKnownConfigurationBlocking(Mockito.any(), Mockito.anyMap()))
                .thenReturn(TestUtil.successfulUnaryCall(response));

        var baseKey = Planner.fetchBaseKey(wellknownService);
        assertThat(baseKey).isEmpty();
    }

    @Test
    void fetchBaseKeyWithMissingFields() {
        var wellknownService = Mockito.mock(WellKnownServiceClientInterface.class);
        // Missing 'kid', 'pem', and 'algorithm' in public_key
        var baseKeyJson = "{\"kas_url\":\"https://example.com/base_key\",\"public_key\":{}}";
        var val = Value.newBuilder().setStringValue(baseKeyJson).build();
        var config = Struct.newBuilder().putFields("base_key", val).build();
        var response = GetWellKnownConfigurationResponse
                .newBuilder()
                .setConfiguration(config)
                .build();

        Mockito.when(wellknownService.getWellKnownConfigurationBlocking(Mockito.any(), Mockito.anyMap()))
                .thenReturn(TestUtil.successfulUnaryCall(response));

        var baseKey = Planner.fetchBaseKey(wellknownService);
        assertThat(baseKey).isEmpty();
    }

    @Test
    void generatePlanFromProvidedKases() {
        var kas1 = new Config.KASInfo();
        kas1.URL = "https://kas1.example.com";
        kas1.KID = "kid1";
        kas1.Algorithm = "rsa:2048";

        var kas2 = new Config.KASInfo();
        kas2.URL = "https://kas2.example.com";
        kas2.KID = "kid2";
        kas2.Algorithm = "ec:secp256";

        var tdfConfig = new Config.TDFConfig();
        tdfConfig.kasInfoList.add(kas1);
        tdfConfig.kasInfoList.add(kas2);

        var planner = new Planner(tdfConfig, new FakeServicesBuilder().build(), (ignore1, ignored2) -> { throw new IllegalArgumentException("no granter needed"); });
        List<Autoconfigure.KeySplitStep> splitPlan = planner.generatePlanFromProvidedKases(tdfConfig.kasInfoList);

        assertThat(splitPlan).asList().hasSize(2);
        assertThat(splitPlan.get(0).kas).isEqualTo("https://kas1.example.com");
        assertThat(splitPlan.get(0).kid).isEqualTo("kid1");

        assertThat(splitPlan.get(1).kas).isEqualTo("https://kas2.example.com");
        assertThat(splitPlan.get(1).kid).isEqualTo("kid2");

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
                    ret.Algorithm = "rsa:4096";
                    ret.KID = "kid3";
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
                new Autoconfigure.KeySplitStep("https://kas1.example.com", "split1", null),
                new Autoconfigure.KeySplitStep("https://kas4.example.com", "split1", "kid4"),
                new Autoconfigure.KeySplitStep("https://kas2.example.com", "split2", "kid2"),
                new Autoconfigure.KeySplitStep("https://kas3.example.com", "split2", "kid3")
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
        assertThat(kasInfo3.Algorithm).isEqualTo("rsa:4096");
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

        var splitStep1 = new Autoconfigure.KeySplitStep(kas1.URL, "split1", kas1.KID);
        var splitStep2 = new Autoconfigure.KeySplitStep(kas2.URL, "split2", kas2.KID);

        var tdfConfig = new Config.TDFConfig();
        tdfConfig.autoconfigure = false;
        tdfConfig.kasInfoList.add(kas1);
        tdfConfig.kasInfoList.add(kas2);
        tdfConfig.splitPlan = List.of(splitStep1, splitStep2);

        var planner = new Planner(tdfConfig, new FakeServicesBuilder().setKas(kas).build(), (ignore1, ignored2) -> { throw new IllegalArgumentException("no granter needed"); });

        // Act
        Map<String, List<Config.KASInfo>> splits = planner.getSplits(tdfConfig);

        // Assert
        Assertions.assertThat(splits).hasSize(2);
        Assertions.assertThat(splits.get("split1")).extracting("URL").containsExactly("https://kas1.example.com");
        Assertions.assertThat(splits.get("split2")).extracting("URL").containsExactly("https://kas2.example.com");
    }
}