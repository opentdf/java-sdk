package io.opentdf.platform.sdk;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.security.Security;

public class CryptoProviderSetupExtension implements BeforeAllCallback {
    private BouncyCastleProvider securityProvider;

    @Override
    public void beforeAll(ExtensionContext extensionContext) throws Exception {
        if (this.securityProvider == null) {
            Security.addProvider(this.securityProvider = new BouncyCastleProvider());
        }
    }
}
