package io.opentdf.platform.sdk;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

final class CompositeX509ExtendedTrustManager extends X509ExtendedTrustManager {

    private final List<X509ExtendedTrustManager> delegates;
    private final X509Certificate[] acceptedIssuers;

    CompositeX509ExtendedTrustManager(List<X509ExtendedTrustManager> delegates) {
        if (delegates == null || delegates.isEmpty()) {
            throw new IllegalArgumentException("at least one trust manager is required");
        }
        this.delegates = Collections.unmodifiableList(new ArrayList<>(delegates));
        Set<X509Certificate> issuers = new LinkedHashSet<>();
        for (X509ExtendedTrustManager tm : this.delegates) {
            X509Certificate[] tmIssuers = tm.getAcceptedIssuers();
            if (tmIssuers != null) {
                Collections.addAll(issuers, tmIssuers);
            }
        }
        this.acceptedIssuers = issuers.toArray(new X509Certificate[0]);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        CertificateException last = null;
        for (X509ExtendedTrustManager tm : delegates) {
            try {
                tm.checkClientTrusted(chain, authType);
                return;
            } catch (CertificateException e) {
                last = e;
            }
        }
        throw last;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        CertificateException last = null;
        for (X509ExtendedTrustManager tm : delegates) {
            try {
                tm.checkClientTrusted(chain, authType, socket);
                return;
            } catch (CertificateException e) {
                last = e;
            }
        }
        throw last;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        CertificateException last = null;
        for (X509ExtendedTrustManager tm : delegates) {
            try {
                tm.checkClientTrusted(chain, authType, engine);
                return;
            } catch (CertificateException e) {
                last = e;
            }
        }
        throw last;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        CertificateException last = null;
        for (X509ExtendedTrustManager tm : delegates) {
            try {
                tm.checkServerTrusted(chain, authType);
                return;
            } catch (CertificateException e) {
                last = e;
            }
        }
        throw last;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        CertificateException last = null;
        for (X509ExtendedTrustManager tm : delegates) {
            try {
                tm.checkServerTrusted(chain, authType, socket);
                return;
            } catch (CertificateException e) {
                last = e;
            }
        }
        throw last;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        CertificateException last = null;
        for (X509ExtendedTrustManager tm : delegates) {
            try {
                tm.checkServerTrusted(chain, authType, engine);
                return;
            } catch (CertificateException e) {
                last = e;
            }
        }
        throw last;
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return acceptedIssuers.clone();
    }
}
