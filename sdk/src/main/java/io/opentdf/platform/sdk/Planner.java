package io.opentdf.platform.sdk;

import com.connectrpc.ConnectException;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.annotations.SerializedName;
import io.opentdf.platform.policy.Algorithm;
import io.opentdf.platform.policy.SimpleKasKey;
import io.opentdf.platform.policy.SimpleKasPublicKey;
import io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationRequest;
import io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse;
import io.opentdf.platform.wellknownconfiguration.WellKnownServiceClientInterface;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.BiFunction;


public class Planner {
    private static final String BASE_KEY = "base_key";
    private final Config.TDFConfig tdfConfig;
    private final SDK.Services services;


    private static final Logger logger = LoggerFactory.getLogger(Planner.class);

    public Planner(Config.TDFConfig config, SDK.Services services, BiFunction<SDK.Services, Config.TDFConfig, Autoconfigure.Granter> granterFactory) {
        this.tdfConfig = Objects.requireNonNull(config);
        this.services = Objects.requireNonNull(services);
    }

    private static String getUUID() {
        return UUID.randomUUID().toString();
    }

    Map<String, List<Config.KASInfo>> getSplits(Config.TDFConfig tdfConfig) {
        List<Autoconfigure.KeySplitStep> splitPlan;
        if (tdfConfig.autoconfigure) {
            if (tdfConfig.splitPlan != null && !tdfConfig.splitPlan.isEmpty()) {
                throw new IllegalArgumentException("cannot use autoconfigure with a split plan provided in the TDFConfig");
            }
            splitPlan = getAutoconfigurePlan(services, tdfConfig);
        } else if (tdfConfig.splitPlan == null || tdfConfig.splitPlan.isEmpty()) {
            splitPlan = generatePlanFromProvidedKases(tdfConfig.kasInfoList);
        } else {
            splitPlan = tdfConfig.splitPlan;
        }

        if (tdfConfig.kasInfoList.isEmpty() && splitPlan.isEmpty()) {
            throw new SDK.KasInfoMissing("kas information is missing, no key access template specified or inferred");
        }
        return resolveKeys(splitPlan);
    }

    private static List<Autoconfigure.KeySplitStep> getAutoconfigurePlan(SDK.Services services, Config.TDFConfig tdfConfig) {
        Autoconfigure.Granter granter = Autoconfigure.createGranter(services, tdfConfig);
        return granter.getSplits(defaultKases(tdfConfig), Planner::getUUID, () -> Planner.fetchBaseKey(services.wellknown()));
    }


    List<Autoconfigure.KeySplitStep> generatePlanFromProvidedKases(List<Config.KASInfo> kases) {
        if (kases.size() == 1) {
            var kasInfo = kases.get(0);
            return Collections.singletonList(new Autoconfigure.KeySplitStep(kasInfo.URL, "", kasInfo.KID));
        }
        List<Autoconfigure.KeySplitStep> splitPlan = new ArrayList<>();
        for (var kasInfo : kases) {
            splitPlan.add(new Autoconfigure.KeySplitStep(kasInfo.URL, getUUID(), kasInfo.KID));
        }
        return splitPlan;
    }

    static Optional<SimpleKasKey> fetchBaseKey(WellKnownServiceClientInterface wellknown) {
        var responseMessage = wellknown
                .getWellKnownConfigurationBlocking(GetWellKnownConfigurationRequest.getDefaultInstance(), Collections.emptyMap())
                .execute();
        GetWellKnownConfigurationResponse response;
        try {
            response = RequestHelper.getOrThrow(responseMessage);
        } catch (ConnectException e) {
            logger.error("unable to retrieve configuration from well known endpoint", e);
            throw new SDKException("unable to retrieve base key from well known endpoint", e);
        }

        String baseKeyJson;
        try {
            baseKeyJson = response
                    .getConfiguration()
                    .getFieldsOrThrow(BASE_KEY)
                    .getStringValue();
        } catch (IllegalArgumentException e) {
            logger.info( "no `" + BASE_KEY + "` found in well known configuration.", e);
            return Optional.empty();
        }

        BaseKey baseKey;
        try {
            baseKey = gson.fromJson(baseKeyJson, BaseKey.class);
        } catch (JsonSyntaxException e) {
            throw new SDKException("base key in well known configuration is malformed [" + baseKeyJson + "]", e);
        }

        if (baseKey == null || baseKey.kasUrl == null || baseKey.publicKey == null || baseKey.publicKey.kid == null || baseKey.publicKey.pem == null || baseKey.publicKey.algorithm == null) {
            logger.error("base key in well known configuration is missing required fields [{}]. base key will not be used", baseKeyJson);
            return Optional.empty();
        }

        return Optional.of(SimpleKasKey.newBuilder()
                .setKasUri(baseKey.kasUrl)
                .setPublicKey(
                        SimpleKasPublicKey.newBuilder()
                        .setKid(baseKey.publicKey.kid)
                        .setAlgorithm(baseKey.publicKey.algorithm)
                        .setPem(baseKey.publicKey.pem)
                        .build())
                .build());
    }

    private static final Gson gson = new Gson();

    private static class BaseKey {
        @SerializedName("kas_url")
        String kasUrl;

        @SerializedName("public_key")
        Key publicKey;

        private static class Key {
            String kid;
            String pem;
            Algorithm algorithm;
        }
    }

    Map<String, List<Config.KASInfo>> resolveKeys(List<Autoconfigure.KeySplitStep> splitPlan) {
        Map<String, List<Config.KASInfo>> conjunction = new HashMap<>();
        var latestKASInfo = new HashMap<String, Config.KASInfo>();
        // Seed anything passed in manually
        for (Config.KASInfo kasInfo : tdfConfig.kasInfoList) {
            if (kasInfo.PublicKey != null && !kasInfo.PublicKey.isEmpty()) {
                latestKASInfo.put(kasInfo.URL, kasInfo);
            }
        }

        for (Autoconfigure.KeySplitStep splitInfo: splitPlan) {
            // Public key was passed in with kasInfoList
            // TODO First look up in attribute information / add to split plan?
            Config.KASInfo ki = latestKASInfo.get(splitInfo.kas);
            if (ki == null || ki.PublicKey == null || ki.PublicKey.isBlank() || (splitInfo.kid != null && !splitInfo.kid.equals(ki.KID))) {
                logger.info("no public key provided for KAS at {}, retrieving", splitInfo.kas);
                var getKI = new Config.KASInfo();
                getKI.URL = splitInfo.kas;
                getKI.Algorithm = tdfConfig.wrappingKeyType.toString();
                getKI.KID = splitInfo.kid;
                getKI = services.kas().getPublicKey(getKI);
                latestKASInfo.put(splitInfo.kas, getKI);
                ki = getKI;
            }
            conjunction.computeIfAbsent(splitInfo.splitID, s -> new ArrayList<>()).add(ki);
        }
        return conjunction;
    }

    static List<String> defaultKases(Config.TDFConfig config) {
        List<String> allk = new ArrayList<>();
        List<String> defk = new ArrayList<>();

        for (Config.KASInfo kasInfo : config.kasInfoList) {
            if (kasInfo.Default != null && kasInfo.Default) {
                defk.add(kasInfo.URL);
            } else if (defk.isEmpty()) {
                allk.add(kasInfo.URL);
            }
        }
        return defk.isEmpty() ? allk : defk;
    }
}
