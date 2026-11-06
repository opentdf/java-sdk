package io.opentdf.platform.sdk;

import com.connectrpc.ConnectException;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;
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
import java.util.stream.Collectors;


public class Planner {
    private static final String BASE_KEY = "base_key";
    private final Config.TDFConfig tdfConfig;
    private final SDK.Services services;
    private final BiFunction<SDK.Services, Config.TDFConfig, Autoconfigure.Granter> granterFactory;


    private static final Logger logger = LoggerFactory.getLogger(Planner.class);

    Planner(Config.TDFConfig config, SDK.Services services, BiFunction<SDK.Services, Config.TDFConfig, Autoconfigure.Granter> granterFactory) {
        this.tdfConfig = Objects.requireNonNull(config);
        this.services = Objects.requireNonNull(services);
        this.granterFactory = granterFactory;
    }

    private static String getUUID() {
        return UUID.randomUUID().toString();
    }

    Map<String, List<Config.KASInfo>> getSplits() {
        List<Autoconfigure.KeySplitTemplate> splitPlan;
        if (tdfConfig.autoconfigure) {
            if (tdfConfig.splitPlan != null && !tdfConfig.splitPlan.isEmpty()) {
                throw new IllegalArgumentException("cannot use autoconfigure with a split plan provided in the TDFConfig");
            }
            splitPlan = getAutoconfigurePlan(services, tdfConfig);
        } else if (tdfConfig.splitPlan == null || tdfConfig.splitPlan.isEmpty()) {
            splitPlan = generatePlanFromProvidedKases(tdfConfig.kasInfoList);
        } else {
            splitPlan = tdfConfig.splitPlan.stream()
                    .map(k -> new Autoconfigure.KeySplitTemplate(k.kas, k.splitID, null, null))
                    .collect(Collectors.toList());
        }

        if (splitPlan.isEmpty()) {
            throw new SDK.KasInfoMissing("no plan was constructed via autoconfigure, explicit split plan or provided kases");
        }
        return resolveKeys(splitPlan);
    }

    private List<Autoconfigure.KeySplitTemplate> getAutoconfigurePlan(SDK.Services services, Config.TDFConfig tdfConfig) {
        Autoconfigure.Granter granter = granterFactory.apply(services, tdfConfig);
        return granter.getSplits(defaultKases(tdfConfig), Planner::getUUID, () -> Planner.fetchBaseKey(services.wellknown()));
    }


    List<Autoconfigure.KeySplitTemplate> generatePlanFromProvidedKases(List<Config.KASInfo> kases) {
        if (kases.size() == 1) {
            var kasInfo = kases.get(0);
            return Collections.singletonList(new Autoconfigure.KeySplitTemplate(kasInfo.URL, "", kasInfo.KID, null));
        }
        List<Autoconfigure.KeySplitTemplate> splitPlan = new ArrayList<>();
        for (var kasInfo : kases) {
            var keyType = kasInfo.Algorithm == null ? null : KeyType.fromString(kasInfo.Algorithm);
            splitPlan.add(new Autoconfigure.KeySplitTemplate(kasInfo.URL, getUUID(), kasInfo.KID, keyType));
        }
        return splitPlan;
    }

    /**
     * Fetches the base key from the platform's structured well-known configuration.
     *
     * @return a supported base key, or empty when the response type or required field values are invalid
     * @throws SDKException if the configuration cannot be retrieved
     */
    static Optional<SimpleKasKey> fetchBaseKey(WellKnownServiceClientInterface wellknown) {
        var responseMessage = wellknown
                .getWellKnownConfigurationBlocking(GetWellKnownConfigurationRequest.getDefaultInstance(), Collections.emptyMap())
                .execute();
        GetWellKnownConfigurationResponse response;
        try {
            response = RequestHelper.getOrThrow(responseMessage);
        } catch (ConnectException e) {
            throw new SDKException("unable to retrieve base key from well known endpoint", e);
        }

        var baseKeyValue = response.getConfiguration().getFieldsMap().get(BASE_KEY);
        if (baseKeyValue == null) {
            logger.info("no `{}` found in well known configuration", BASE_KEY);
            return Optional.empty();
        }

        if (baseKeyValue.getKindCase() != Value.KindCase.STRUCT_VALUE) {
            logger.error("base key in well known configuration has an invalid type; base key will not be used");
            return Optional.empty();
        }

        var baseKey = baseKeyValue.getStructValue();
        var publicKeyValue = baseKey.getFieldsMap().get("public_key");
        if (publicKeyValue == null || publicKeyValue.getKindCase() != Value.KindCase.STRUCT_VALUE) {
            logger.error("base key in well known configuration is missing valid required fields; base key will not be used");
            return Optional.empty();
        }

        var publicKey = publicKeyValue.getStructValue();
        var kasUri = stringField(baseKey, "kas_uri");
        var kid = stringField(publicKey, "kid");
        var pem = stringField(publicKey, "pem");
        var algorithmName = stringField(publicKey, "algorithm");
        if (isMissing(kasUri) || isMissing(kid) || isMissing(pem) || isMissing(algorithmName)) {
            logger.error("base key in well known configuration is missing valid required fields; base key will not be used");
            return Optional.empty();
        }

        Algorithm algorithm;
        try {
            algorithm = KeyType.fromString(algorithmName).getAlgorithm();
        } catch (IllegalArgumentException e) {
            logger.error("base key in well known configuration has an unsupported algorithm; base key will not be used");
            return Optional.empty();
        }

        return Optional.of(SimpleKasKey.newBuilder()
                .setKasUri(kasUri)
                .setPublicKey(
                        SimpleKasPublicKey.newBuilder()
                        .setKid(kid)
                        .setAlgorithm(algorithm)
                        .setPem(pem)
                        .build())
                .build());
    }

    /** Returns the named protobuf string value, or null when the field is absent or has another type. */
    private static String stringField(Struct fields, String name) {
        var value = fields.getFieldsMap().get(name);
        return value != null && value.getKindCase() == Value.KindCase.STRING_VALUE
                ? value.getStringValue() : null;
    }

    /** Treats null and blank strings as missing required field values. */
    private static boolean isMissing(String value) {
        return value == null || value.isBlank();
    }

    Map<String, List<Config.KASInfo>> resolveKeys(List<Autoconfigure.KeySplitTemplate> splitPlan) {
        Map<String, List<Config.KASInfo>> conjunction = new HashMap<>();
        var latestKASInfo = new HashMap<String, Config.KASInfo>();
        // Seed anything passed in manually
        for (Config.KASInfo kasInfo : tdfConfig.kasInfoList) {
            if (kasInfo.PublicKey != null && !kasInfo.PublicKey.isEmpty()) {
                latestKASInfo.put(kasInfo.URL, kasInfo);
            }
        }

        for (var splitInfo: splitPlan) {
            // Public key was passed in with kasInfoList
            // TODO First look up in attribute information / add to split plan?
            Config.KASInfo ki = latestKASInfo.get(splitInfo.kas);
            if (ki == null || ki.PublicKey == null || ki.PublicKey.isBlank() || (splitInfo.kid != null && !splitInfo.kid.equals(ki.KID))) {
                logger.info("no public key provided for KAS at {}, retrieving", splitInfo.kas);
                var getKI = new Config.KASInfo();
                getKI.URL = splitInfo.kas;
                getKI.KID = splitInfo.kid;
                getKI.Algorithm = splitInfo.keyType == null
                        ? (tdfConfig.wrappingKeyType == null ? null : tdfConfig.wrappingKeyType.toString())
                        : splitInfo.keyType.toString();
                ki = services.kas().getPublicKey(getKI);
                latestKASInfo.put(splitInfo.kas, ki);
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
