package io.opentdf.platform.sdk;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Builds {@link SSLSocketFactory} and {@link X509ExtendedTrustManager} instances for verifying
 * X.509 certificate chains during TLS handshakes.
 *
 * <p>Implemented entirely on top of provider-agnostic JCA APIs ({@link CertificateFactory},
 * {@link KeyStore}, {@link TrustManagerFactory}, {@link SSLContext}). The actual cryptographic
 * work is fulfilled by whichever {@link java.security.Provider} is registered with the JVM,
 * including FIPS-mode providers.
 */
public final class TrustProvider {

    private final SSLSocketFactory sslSocketFactory;
    private final X509ExtendedTrustManager trustManager;
    private final SSLContext sslContext;

    private TrustProvider(SSLContext sslContext, X509ExtendedTrustManager trustManager) {
        this.sslContext = sslContext;
        this.trustManager = trustManager;
        this.sslSocketFactory = sslContext.getSocketFactory();
    }

    public X509ExtendedTrustManager getTrustManager() {
        return trustManager;
    }

    public SSLContext getSslContext() {
        return sslContext;
    }

    public SSLSocketFactory getSslSocketFactory() {
        return sslSocketFactory;
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builds a {@link TrustProvider} that trusts JVM default cacerts plus every {@code .pem} or
     * {@code .crt} certificate found in the supplied directory.
     */
    public static TrustProvider fromDirectory(String certsDirPath) throws IOException, GeneralSecurityException {
        File certsDir = new File(certsDirPath);
        File[] certFiles = certsDir.listFiles((dir, name) -> name.endsWith(".pem") || name.endsWith(".crt"));
        if (certFiles == null) {
            throw new IOException("not a directory or unreadable: " + certsDirPath);
        }
        Builder builder = builder().withDefaultTrustMaterial();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        for (File certFile : certFiles) {
            try (InputStream in = new FileInputStream(certFile)) {
                Collection<? extends Certificate> certs = cf.generateCertificates(in);
                List<X509Certificate> x509s = new ArrayList<>(certs.size());
                for (Certificate c : certs) {
                    if (c instanceof X509Certificate) {
                        x509s.add((X509Certificate) c);
                    }
                }
                builder.withTrustMaterial(x509s.toArray(new X509Certificate[0]));
            }
        }
        return builder.build();
    }

    /**
     * Builds a {@link TrustProvider} that trusts JVM default cacerts plus the trusted-certificate
     * entries in the supplied keystore.
     */
    public static TrustProvider fromKeyStore(Path keystorePath, char[] password) throws IOException, GeneralSecurityException {
        if (!Files.isRegularFile(keystorePath)) {
            throw new IOException("keystore not found: " + keystorePath);
        }
        KeyStore ks;
        try (InputStream in = Files.newInputStream(keystorePath)) {
            ks = loadKeyStore(in, password);
        }
        return builder().withDefaultTrustMaterial().withTrustMaterial(ks).build();
    }

    /**
     * Builds a {@link TrustProvider} that accepts every server certificate. Intended only for
     * tests and {@code --insecure} CLI flows.
     */
    public static TrustProvider insecure() {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            X509ExtendedTrustManager trustAll = new InsecureTrustManager();
            ctx.init(new KeyManager[0], new TrustManager[]{trustAll}, new SecureRandom());
            return new TrustProvider(ctx, trustAll);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("failed to build insecure TrustProvider", e);
        }
    }

    private static KeyStore loadKeyStore(InputStream in, char[] password)
            throws IOException, GeneralSecurityException {
        // Try JKS first since it remains the JVM default; fall back to PKCS12 which is portable
        // across both bcprov-jdk18on and bc-fips. We do not pin a provider; whichever provider is
        // registered fulfills the request.
        byte[] bytes = readAll(in);
        KeyStoreException last = null;
        for (String type : new String[]{KeyStore.getDefaultType(), "JKS", "PKCS12"}) {
            try {
                KeyStore ks = KeyStore.getInstance(type);
                ks.load(new java.io.ByteArrayInputStream(bytes), password);
                return ks;
            } catch (KeyStoreException e) {
                last = e;
            } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
                // wrong format or wrong password — try next type
                last = new KeyStoreException(e);
            }
        }
        throw last != null ? last : new KeyStoreException("could not load keystore");
    }

    private static byte[] readAll(InputStream in) throws IOException {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) >= 0) {
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    private static X509ExtendedTrustManager extractTrustManager(KeyStore trustStore)
            throws GeneralSecurityException {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509ExtendedTrustManager) {
                return (X509ExtendedTrustManager) tm;
            }
        }
        throw new NoSuchAlgorithmException("no X509ExtendedTrustManager available from provider");
    }

    public static final class Builder {
        private boolean includeDefault;
        private final List<KeyStore> keyStores = new ArrayList<>();
        private final List<X509Certificate> certificates = new ArrayList<>();

        private Builder() {
        }

        /**
         * Include the JVM default cacerts (i.e. those returned by initialising a
         * {@link TrustManagerFactory} with a {@code null} keystore).
         */
        public Builder withDefaultTrustMaterial() {
            this.includeDefault = true;
            return this;
        }

        public Builder withTrustMaterial(X509Certificate... certs) {
            if (certs != null) {
                Collections.addAll(this.certificates, certs);
            }
            return this;
        }

        public Builder withTrustMaterial(Collection<X509Certificate> certs) {
            if (certs != null) {
                this.certificates.addAll(certs);
            }
            return this;
        }

        public Builder withTrustMaterial(KeyStore keyStore) {
            if (keyStore != null) {
                this.keyStores.add(keyStore);
            }
            return this;
        }

        public Builder withTrustMaterial(Path keystorePath, char[] password) throws IOException, GeneralSecurityException {
            try (InputStream in = Files.newInputStream(keystorePath)) {
                this.keyStores.add(loadKeyStore(in, password));
            }
            return this;
        }

        public TrustProvider build() {
            try {
                List<X509ExtendedTrustManager> trustManagers = new ArrayList<>();

                if (includeDefault) {
                    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                    tmf.init((KeyStore) null);
                    for (TrustManager tm : tmf.getTrustManagers()) {
                        if (tm instanceof X509ExtendedTrustManager) {
                            trustManagers.add((X509ExtendedTrustManager) tm);
                        }
                    }
                }

                for (KeyStore ks : keyStores) {
                    trustManagers.add(extractTrustManager(ks));
                }

                if (!certificates.isEmpty()) {
                    KeyStore custom = newEmptyKeyStore();
                    int i = 0;
                    for (X509Certificate cert : certificates) {
                        custom.setCertificateEntry("trust-anchor-" + (i++), cert);
                    }
                    trustManagers.add(extractTrustManager(custom));
                }

                if (trustManagers.isEmpty()) {
                    throw new IllegalStateException("TrustProvider requires at least one source of trust material");
                }

                X509ExtendedTrustManager combined = trustManagers.size() == 1
                        ? trustManagers.get(0)
                        : new CompositeX509ExtendedTrustManager(trustManagers);

                SSLContext ctx = SSLContext.getInstance("TLS");
                ctx.init(new KeyManager[0], new TrustManager[]{combined}, new SecureRandom());
                return new TrustProvider(ctx, combined);
            } catch (GeneralSecurityException | IOException e) {
                throw new IllegalStateException("failed to build TrustProvider", e);
            }
        }

        private static KeyStore newEmptyKeyStore() throws GeneralSecurityException, IOException {
            // PKCS12 is supported by both stock JDK and BC (FIPS and non-FIPS).
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            return ks;
        }
    }

    private static final class InsecureTrustManager extends X509ExtendedTrustManager {
        private static final X509Certificate[] EMPTY = new X509Certificate[0];

        @Override public void checkClientTrusted(X509Certificate[] chain, String authType) { }
        @Override public void checkClientTrusted(X509Certificate[] chain, String authType, java.net.Socket socket) { }
        @Override public void checkClientTrusted(X509Certificate[] chain, String authType, javax.net.ssl.SSLEngine engine) { }
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType) { }
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType, java.net.Socket socket) { }
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType, javax.net.ssl.SSLEngine engine) { }
        @Override public X509Certificate[] getAcceptedIssuers() { return EMPTY; }
    }
}
