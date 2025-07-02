package io.opentdf.platform.sdk;

import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import io.opentdf.platform.policy.Algorithm;
import io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse;
import io.opentdf.platform.wellknownconfiguration.WellKnownServiceClientInterface;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.List;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.*;

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
}