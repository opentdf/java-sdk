package io.opentdf.platform.sdk;

import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import io.opentdf.platform.policy.Algorithm;
import io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse;
import io.opentdf.platform.wellknownconfiguration.WellKnownServiceClientInterface;
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

        var planner = new Planner(new Config.TDFConfig(), new FakeServicesBuilder().setWellknownService(wellknownService).build());

        var baseKey = planner.fetchBaseKey();
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

        var planner = new Planner(new Config.TDFConfig(), new FakeServicesBuilder().setWellknownService(wellknownService).build());

        var baseKey = planner.fetchBaseKey();
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

        var planner = new Planner(tdfConfig, new FakeServicesBuilder().build());
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
                assertThat(kasInfo.Algorithm).isNullOrEmpty();
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
        var planner = new Planner(new Config.TDFConfig(), new FakeServicesBuilder().setKas(kas).build());
        var plan = List.of(
                new Autoconfigure.KeySplitStep("https://kas1.example.com", "split1", null),
                new Autoconfigure.KeySplitStep("https://kas2.example.com", "split2", "kid2"),
                new Autoconfigure.KeySplitStep("https://kas3.example.com", "split2", "kid3")
        );
        Map<String, List<Config.KASInfo>> filledInPlan = planner.resolveKeys(plan);
        assertThat(filledInPlan.keySet().stream().collect(Collectors.toList())).asList().containsExactlyInAnyOrder("split1", "split2");
        assertThat(filledInPlan.get("split1")).asList().hasSize(1);
        var split1KasInfo = filledInPlan.get("split1").get(0);
        assertThat(split1KasInfo.URL).isEqualTo("https://kas1.example.com");
        assertThat(split1KasInfo.KID).isEqualTo("kid1");
        assertThat(split1KasInfo.Algorithm).isEqualTo("rsa:2048");
        assertThat(split1KasInfo.PublicKey).isEqualTo("pem1");
        assertThat(filledInPlan.get("split2")).asList().hasSize(2);
        var split2KasInfo = filledInPlan.get("split2").stream().filter(kasInfo -> "kid2".equals(kasInfo.KID)).findFirst().get();
        assertThat(split2KasInfo.URL).isEqualTo("https://kas2.example.com");
        assertThat(split2KasInfo.Algorithm).isEqualTo("ec:secp256r1");
        assertThat(split2KasInfo.PublicKey).isEqualTo("pem2");
        var split3KasInfo = filledInPlan.get("split2").stream().filter(kasInfo -> "kid3".equals(kasInfo.KID)).findFirst().get();
        assertThat(split3KasInfo.URL).isEqualTo("https://kas3.example.com");
        assertThat(split3KasInfo.Algorithm).isEqualTo("rsa:4096");
        assertThat(split3KasInfo.PublicKey).isEqualTo("pem3");
    }
}