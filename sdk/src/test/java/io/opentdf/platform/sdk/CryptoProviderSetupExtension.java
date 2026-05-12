package io.opentdf.platform.sdk;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

public class CryptoProviderSetupExtension implements BeforeAllCallback {
    private BouncyCastleProvider securityProvider;

    @Override
    public synchronized void beforeAll(ExtensionContext extensionContext) {
        if (this.securityProvider == null) {
            var existingProviders =  Security.getProviders();
            Arrays.asList(existingProviders).stream().map(Provider::getName).forEach(Security::removeProvider);
            if (Security.getProviders().length != 0) {
                throw new IllegalStateException("unable to remove all providers");
            }

            Security.addProvider(this.securityProvider = new BouncyCastleProvider());
        }
    }
}
