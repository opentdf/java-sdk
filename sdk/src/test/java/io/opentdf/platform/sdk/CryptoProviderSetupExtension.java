package io.opentdf.platform.sdk;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
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
            Security.insertProviderAt(this.securityProvider = new BouncyCastleProvider(), 1);
            Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);
        }
    }
}
