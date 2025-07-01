package io.opentdf.platform.sdk;

import io.opentdf.platform.policy.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

public class Planner {
    private final Config.TDFConfig tdfConfig;
    private final SDK.Services sdkServices;
    private final Autoconfigure.Granter granter;

    private static final Logger logger = LoggerFactory.getLogger(Planner.class);

    public Planner(Config.TDFConfig config, SDK.Services services) {
        tdfConfig = Objects.requireNonNull(config);
        sdkServices = Objects.requireNonNull(services) ;

        List<String> dk = defaultKases(tdfConfig);
        if (tdfConfig.autoconfigure) {
            if (tdfConfig.splitPlan != null && !tdfConfig.splitPlan.isEmpty()) {
                throw new IllegalArgumentException("cannot use autoconfigure with a split plan provided in the TDFConfig");
            }
            Autoconfigure.Granter granter = new Autoconfigure.Granter(new ArrayList<>());
            if (tdfConfig.attributeValues != null && !tdfConfig.attributeValues.isEmpty()) {
                granter = Autoconfigure.newGranterFromAttributes(services.kas().getKeyCache(), tdfConfig.attributeValues.toArray(new Value[0]));
            } else if (tdfConfig.attributes != null && !tdfConfig.attributes.isEmpty()) {
                granter = Autoconfigure.newGranterFromService(services.attributes(), services.kas().getKeyCache(),
                        tdfConfig.attributes.toArray(new Autoconfigure.AttributeValueFQN[0]));
            }

            this.granter = granter;
        } else {
            this.granter = null;
        }

        if (tdfConfig.kasInfoList.isEmpty() && tdfConfig.splitPlan.isEmpty()) {
            throw new SDK.KasInfoMissing("kas information is missing, no key access template specified or inferred");
        }
    }

    Map<String, List<Config.KASInfo>> getSplits(Config.TDFConfig tdfConfig) {
        var latestKASInfo = new HashMap<String, Config.KASInfo>();
        // Seed anything passed in manually
        for (Config.KASInfo kasInfo : tdfConfig.kasInfoList) {
            if (kasInfo.PublicKey != null && !kasInfo.PublicKey.isEmpty()) {
                latestKASInfo.put(kasInfo.URL, kasInfo);
            }
        }

        // split plan: restructure by conjunctions
        Map<String, List<Config.KASInfo>> conjunction = new HashMap<>();

        for (Autoconfigure.KeySplitStep splitInfo : tdfConfig.splitPlan) {
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
