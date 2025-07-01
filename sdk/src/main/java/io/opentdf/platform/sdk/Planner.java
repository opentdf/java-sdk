package io.opentdf.platform.sdk;

import io.opentdf.platform.policy.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import static io.opentdf.platform.sdk.Autoconfigure.Granter.generatePlanFromDefaultKases;

public class Planner {
    private final Config.TDFConfig tdfConfig;
    private final SDK.Services sdkServices;

    private static final Logger logger = LoggerFactory.getLogger(Planner.class);

    public Planner(Config.TDFConfig config, SDK.Services services) {
        tdfConfig = Objects.requireNonNull(config);
        sdkServices = Objects.requireNonNull(services) ;
    }

    private static String getUUID() {
        return UUID.randomUUID().toString();
    }

    Map<String, List<Config.KASInfo>> getSplits(Config.TDFConfig tdfConfig) {
        List<Autoconfigure.KeySplitStep> splitPlan;
        List<String> defaultKases = defaultKases(tdfConfig);
        if (tdfConfig.autoconfigure) {
            splitPlan = getAutoconfigurePlan(tdfConfig);
        } else if (tdfConfig.splitPlan == null || tdfConfig.splitPlan.isEmpty()) {
            splitPlan = defaultKases.isEmpty()
                    ? createPlanFromBaseKey()
                    : generatePlanFromDefaultKases(defaultKases, Planner::getUUID);
        } else {
            splitPlan = tdfConfig.splitPlan;
        }

        if (tdfConfig.kasInfoList.isEmpty() && tdfConfig.splitPlan.isEmpty()) {
            throw new SDK.KasInfoMissing("kas information is missing, no key access template specified or inferred");
        }

        // split plan: restructure by conjunctions
        return fillInKeys(tdfConfig, splitPlan);
    }

    private List<Autoconfigure.KeySplitStep> getAutoconfigurePlan(Config.TDFConfig tdfConfig) {
        if (tdfConfig.splitPlan != null && !tdfConfig.splitPlan.isEmpty()) {
            throw new IllegalArgumentException("cannot use autoconfigure with a split plan provided in the TDFConfig");
        }
        Autoconfigure.Granter granter = new Autoconfigure.Granter(new ArrayList<>());
        if (tdfConfig.attributeValues != null && !tdfConfig.attributeValues.isEmpty()) {
            granter = Autoconfigure.newGranterFromAttributes(sdkServices.kas().getKeyCache(), tdfConfig.attributeValues.toArray(new Value[0]));
        } else if (tdfConfig.attributes != null && !tdfConfig.attributes.isEmpty()) {
            granter = Autoconfigure.newGranterFromService(sdkServices.attributes(), sdkServices.kas().getKeyCache(),
                    tdfConfig.attributes.toArray(new Autoconfigure.AttributeValueFQN[0]));
        }
        return granter.getSplits(defaultKases(tdfConfig), Planner::getUUID, Optional::empty);
    }

    private List<Autoconfigure.KeySplitStep> createPlanFromBaseKey() {
        return null;
    }

    private Map<String, List<Config.KASInfo>> fillInKeys(Config.TDFConfig tdfConfig, List<Autoconfigure.KeySplitStep> splitPlan) {
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
                getKI = sdkServices.kas().getPublicKey(getKI);
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
