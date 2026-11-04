package io.opentdf.platform.sdk;

import com.connectrpc.ConnectException;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import com.google.gson.annotations.SerializedName;
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
     * Fetches the base key from structured configuration or the legacy JSON-string format.
     *
     * @return a supported base key, or empty when required field values are missing or invalid
     * @throws SDKException if retrieval fails, legacy JSON is malformed, or a legacy algorithm sentinel is used
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

        BaseKey baseKey;
        if (baseKeyValue.getKindCase() == Value.KindCase.STRUCT_VALUE) {
            baseKey = baseKeyFromStruct(baseKeyValue.getStructValue());
        } else if (baseKeyValue.getKindCase() == Value.KindCase.STRING_VALUE) {
            // Preserve the JSON-string representation accepted by earlier SDK versions.
            try {
                baseKey = baseKeyFromLegacyJson(baseKeyValue.getStringValue());
            } catch (JsonSyntaxException e) {
                throw new SDKException("base key in well known configuration is malformed", e);
            }
        } else {
            logger.error("base key in well known configuration has an invalid type; base key will not be used");
            return Optional.empty();
        }

        if (baseKey == null || isMissing(baseKey.kasUri) || baseKey.publicKey == null
                || isMissing(baseKey.publicKey.kid) || isMissing(baseKey.publicKey.pem)
                || isMissing(baseKey.publicKey.algorithm)) {
            logger.error("base key in well known configuration is missing valid required fields; base key will not be used");
            return Optional.empty();
        }

        if (baseKeyValue.getKindCase() == Value.KindCase.STRING_VALUE
                && ("ALGORITHM_UNSPECIFIED".equals(baseKey.publicKey.algorithm)
                || "UNRECOGNIZED".equals(baseKey.publicKey.algorithm))) {
            // These legacy enum values failed during planning or key construction.
            // Do not turn them into an absent key that allows default-KAS fallback.
            throw new SDKException("base key in well known configuration has an unsupported algorithm");
        }

        Algorithm algorithm;
        try {
            algorithm = baseKeyAlgorithm(baseKey.publicKey.algorithm);
        } catch (IllegalArgumentException e) {
            logger.error("base key in well known configuration has an unsupported algorithm; base key will not be used");
            return Optional.empty();
        }

        return Optional.of(SimpleKasKey.newBuilder()
                .setKasUri(baseKey.kasUri)
                .setPublicKey(
                        SimpleKasPublicKey.newBuilder()
                        .setKid(baseKey.publicKey.kid)
                        .setAlgorithm(algorithm)
                        .setPem(baseKey.publicKey.pem)
                        .build())
                .build());
    }

    /**
     * Reads legacy fields without allowing Gson to coerce numbers or booleans into strings.
     * Missing fields remain subject to the common required-field validation.
     *
     * @return the decoded fields, or null for absent input or non-string primitive field values
     * @throws JsonSyntaxException for malformed JSON or incompatible object, array, or scalar shapes
     */
    private static BaseKey baseKeyFromLegacyJson(String json) {
        var element = gson.fromJson(json, JsonElement.class);
        if (element == null || element.isJsonNull()) {
            return null;
        }
        if (!element.isJsonObject()) {
            throw new JsonSyntaxException("expected an object for the legacy base key");
        }
        var fields = element.getAsJsonObject();
        var valid = hasLegacyStringFields(fields, "kas_uri", "kas_url");
        var publicKey = fields.get("public_key");
        if (publicKey != null && !publicKey.isJsonNull()) {
            if (!publicKey.isJsonObject()) {
                throw new JsonSyntaxException("expected an object for the legacy public key");
            }
            valid &= hasLegacyStringFields(publicKey.getAsJsonObject(), "algorithm", "kid", "pem");
        }
        return valid ? gson.fromJson(json, BaseKey.class) : null;
    }

    /**
     * Checks every named field before DTO conversion, allowing missing and null values.
     * Structural errors retain the legacy exception behavior even if another field is invalid.
     *
     * @return false if a field contains a number or boolean
     * @throws JsonSyntaxException if a field expected to hold a string contains an object or array
     */
    private static boolean hasLegacyStringFields(JsonObject fields, String... names) {
        var valid = true;
        for (var name : names) {
            var value = fields.get(name);
            if (value == null || value.isJsonNull()) {
                continue;
            }
            if (!value.isJsonPrimitive()) {
                throw new JsonSyntaxException("expected a string for legacy base key field: " + name);
            }
            valid &= value.getAsJsonPrimitive().isString();
        }
        return valid;
    }

    /**
     * Extracts structured fields without coercion, leaving absent or wrongly typed fields unset.
     */
    private static BaseKey baseKeyFromStruct(Struct fields) {
        var baseKey = new BaseKey();
        baseKey.kasUri = stringField(fields, "kas_uri");
        var publicKey = fields.getFieldsMap().get("public_key");
        if (publicKey != null && publicKey.getKindCase() == Value.KindCase.STRUCT_VALUE) {
            var keyFields = publicKey.getStructValue();
            baseKey.publicKey = new BaseKey.Key();
            baseKey.publicKey.kid = stringField(keyFields, "kid");
            baseKey.publicKey.pem = stringField(keyFields, "pem");
            baseKey.publicKey.algorithm = stringField(keyFields, "algorithm");
        }
        return baseKey;
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

    /**
     * Resolves supported platform algorithm names and legacy enum names.
     *
     * @throws IllegalArgumentException if the value does not identify a supported key type
     */
    private static Algorithm baseKeyAlgorithm(String value) {
        if (value.startsWith("ALGORITHM_")) {
            var algorithm = Algorithm.valueOf(value);
            KeyType.fromAlgorithm(algorithm);
            return algorithm;
        }

        switch (KeyType.fromString(value)) {
            case RSA2048Key:
                return Algorithm.ALGORITHM_RSA_2048;
            case RSA4096Key:
                return Algorithm.ALGORITHM_RSA_4096;
            case EC256Key:
                return Algorithm.ALGORITHM_EC_P256;
            case EC384Key:
                return Algorithm.ALGORITHM_EC_P384;
            case EC521Key:
                return Algorithm.ALGORITHM_EC_P521;
            case HybridXWingKey:
                return Algorithm.ALGORITHM_HPQT_XWING;
            case HybridSecp256r1MLKEM768Key:
                return Algorithm.ALGORITHM_HPQT_SECP256R1_MLKEM768;
            case HybridSecp384r1MLKEM1024Key:
                return Algorithm.ALGORITHM_HPQT_SECP384R1_MLKEM1024;
            case MLKEM768Key:
                return Algorithm.ALGORITHM_MLKEM_768;
            case MLKEM1024Key:
                return Algorithm.ALGORITHM_MLKEM_1024;
            default:
                throw new IllegalArgumentException("Unsupported base key algorithm: " + value);
        }
    }

    private static final Gson gson = new Gson();

    private static class BaseKey {
        @SerializedName(value = "kas_uri", alternate = {"kas_url"})
        String kasUri;

        @SerializedName("public_key")
        Key publicKey;

        private static class Key {
            String kid;
            String pem;
            String algorithm;
        }
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
