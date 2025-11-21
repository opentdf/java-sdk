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
        kas1.setURL("https://kas1.example.com");
        kas1.setKID("kid1");

        var kas2 = new Config.KASInfo();
        kas2.setURL("https://kas2.example.com");
        kas2.setKID("kid2");
        kas2.setAlgorithm("ec:secp256r1");

        var tdfConfig = new Config.TDFConfig();
        tdfConfig.getKasInfoList().add(kas1);
        tdfConfig.getKasInfoList().add(kas2);

        var planner = new Planner(tdfConfig, new FakeServicesBuilder().build(), (ignore1, ignored2) -> { throw new IllegalArgumentException("no granter needed"); });
        List<Autoconfigure.KeySplitTemplate> splitPlan = planner.generatePlanFromProvidedKases(tdfConfig.getKasInfoList());

        assertThat(splitPlan).asList().hasSize(2);
        assertThat(splitPlan.get(0).getKas()).isEqualTo("https://kas1.example.com");
        assertThat(splitPlan.get(0).getKid()).isEqualTo("kid1");
        assertThat(splitPlan.get(0).getKeyType()).isNull();

        assertThat(splitPlan.get(1).getKas()).isEqualTo("https://kas2.example.com");
        assertThat(splitPlan.get(1).getKid()).isEqualTo("kid2");
        assertThat(splitPlan.get(1).getKeyType()).isEqualTo(KeyType.EC256Key);

        assertThat(splitPlan.get(0).getSplitID()).isNotEqualTo(splitPlan.get(1).getSplitID());
    }

    @Test
    void testFillingInKeysWithAutoConfigure() {
        var kas = Mockito.mock(SDK.KAS.class);
        Mockito.when(kas.getPublicKey(Mockito.any())).thenAnswer(invocation -> {
                Config.KASInfo kasInfo = invocation.getArgument(0, Config.KASInfo.class);
                var ret = new Config.KASInfo();
                ret.setURL(kasInfo.getURL());
                if (Objects.equals(kasInfo.getURL(), "https://kas1.example.com")) {
                    ret.setPublicKey("pem1");
                    ret.setAlgorithm("rsa:2048");
                    ret.setKID("kid1");
                } else if (Objects.equals(kasInfo.getURL(), "https://kas2.example.com")) {
                    ret.setPublicKey("pem2");
                    ret.setAlgorithm("ec:secp256r1");
                    ret.setKID("kid2");
                } else if (Objects.equals(kasInfo.getURL(), "https://kas3.example.com")) {
                    ret.setPublicKey("pem3");
                    ret.setAlgorithm("ec:secp384r1");
                    ret.setKID("kid3");
                    assertThat(kasInfo.getAlgorithm()).isEqualTo("ec:secp384r1");
                } else {
                    throw new IllegalArgumentException("Unexpected KAS URL: " + kasInfo.getURL());
                }
                return ret;
        });
        var tdfConfig = new Config.TDFConfig();
        tdfConfig.setAutoconfigure(true);
        tdfConfig.setWrappingKeyType(KeyType.RSA2048Key);
        tdfConfig.setKasInfoList(List.of(new Config.KASInfo("https://kas4.example.com", "pem4", "kid4", "ec:secp384r1")));

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
        var kasInfo1 = filledInPlan.get("split1").stream().filter(k -> "kid1".equals(k.getKID())).findFirst().get();
        assertThat(kasInfo1.getURL()).isEqualTo("https://kas1.example.com");
        assertThat(kasInfo1.getAlgorithm()).isEqualTo("rsa:2048");
        assertThat(kasInfo1.getPublicKey()).isEqualTo("pem1");
        var kasInfo4 = filledInPlan.get("split1").stream().filter(k -> "kid4".equals(k.getKID())).findFirst().get();
        assertThat(kasInfo4.getURL()).isEqualTo("https://kas4.example.com");
        assertThat(kasInfo4.getAlgorithm()).isEqualTo("ec:secp384r1");
        assertThat(kasInfo4.getPublicKey()).isEqualTo("pem4");

        assertThat(filledInPlan.get("split2")).asList().hasSize(2);
        var kasInfo2 = filledInPlan.get("split2").stream().filter(kasInfo -> "kid2".equals(kasInfo.getKID())).findFirst().get();
        assertThat(kasInfo2.getURL()).isEqualTo("https://kas2.example.com");
        assertThat(kasInfo2.getAlgorithm()).isEqualTo("ec:secp256r1");
        assertThat(kasInfo2.getPublicKey()).isEqualTo("pem2");
        var kasInfo3 = filledInPlan.get("split2").stream().filter(kasInfo -> "kid3".equals(kasInfo.getKID())).findFirst().get();
        assertThat(kasInfo3.getURL()).isEqualTo("https://kas3.example.com");
        assertThat(kasInfo3.getAlgorithm()).isEqualTo("ec:secp384r1");
        assertThat(kasInfo3.getPublicKey()).isEqualTo("pem3");
    }

    @Test
    void returnsOnlyDefaultKasesIfPresent() {
        var kas1 = new Config.KASInfo();
        kas1.setURL("https://kas1.example.com");
        kas1.setDefault(true);

        var kas2 = new Config.KASInfo();
        kas2.setURL("https://kas2.example.com");
        kas2.setDefault(false);

        var kas3 = new Config.KASInfo();
        kas3.setURL("https://kas3.example.com");
        kas3.setDefault(true);

        var config = new Config.TDFConfig();
        config.getKasInfoList().addAll(List.of(kas1, kas2, kas3));

        List<String> result = Planner.defaultKases(config);

        Assertions.assertThat(result).containsExactlyInAnyOrder("https://kas1.example.com", "https://kas3.example.com");
    }

    @Test
    void returnsAllKasesIfNoDefault() {
        var kas1 = new Config.KASInfo();
        kas1.setURL("https://kas1.example.com");
        kas1.setDefault(false);

        var kas2 = new Config.KASInfo();
        kas2.setURL("https://kas2.example.com");
        kas2.setDefault(null); // not set

        var config = new Config.TDFConfig();
        config.getKasInfoList().addAll(List.of(kas1, kas2));

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
            ret.setURL(kasInfo.getURL());
            if (Objects.equals(kasInfo.getURL(), "https://kas1.example.com")) {
                ret.setPublicKey("pem1");
                ret.setAlgorithm("rsa:2048");
                ret.setKID("kid1");
            } else if (Objects.equals(kasInfo.getURL(), "https://kas2.example.com")) {
                ret.setPublicKey("pem2");
                ret.setAlgorithm("ec:secp256r1");
                ret.setKID("kid2");
            } else {
                throw new IllegalArgumentException("Unexpected KAS URL: " + kasInfo.getURL());
            }
            return ret;
        });
        // Arrange
        var kas1 = new Config.KASInfo();
        kas1.setURL("https://kas1.example.com");
        kas1.setKID("kid1");
        kas1.setAlgorithm("rsa:2048");

        var kas2 = new Config.KASInfo();
        kas2.setURL("https://kas2.example.com");
        kas2.setKID("kid2");
        kas2.setAlgorithm("ec:secp256");

        var splitStep1 = new Autoconfigure.KeySplitStep(kas1.getURL(), "split1");
        var splitStep2 = new Autoconfigure.KeySplitStep(kas2.getURL(), "split2");

        var tdfConfig = new Config.TDFConfig();
        tdfConfig.setAutoconfigure(false);
        tdfConfig.getKasInfoList().add(kas1);
        tdfConfig.getKasInfoList().add(kas2);
        tdfConfig.setSplitPlan(List.of(splitStep1, splitStep2));

        var planner = new Planner(tdfConfig, new FakeServicesBuilder().setKas(kas).build(), (ignore1, ignored2) -> { throw new IllegalArgumentException("no granter needed"); });

        // Act
        Map<String, List<Config.KASInfo>> splits = planner.getSplits();

        // Assert
        Assertions.assertThat(splits).hasSize(2);
        Assertions.assertThat(splits.get("split1")).extracting("URL").containsExactly("https://kas1.example.com");
        Assertions.assertThat(splits.get("split2")).extracting("URL").containsExactly("https://kas2.example.com");
    }
}