package io.opentdf.platform.sdk;

import java.util.List;

/**
 * The PolicyObject class represents a policy with a unique identifier and a body containing data attributes.
 */
public class PolicyObject {
    static public class AttributeObject {
        public String attribute;
        public String displayName;
        public boolean isDefault;
        public String pubKey;
        public String kasURL;
    }

    static public class Body {
        public List<AttributeObject> dataAttributes;
        public List<String> dissem;
    }

    public String uuid;
    public Body body;
}
