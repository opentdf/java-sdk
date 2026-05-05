package io.opentdf.platform.sdk;

import com.connectrpc.ResponseMessage;
import com.connectrpc.UnaryBlockingCall;

import java.util.Collections;


import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

public class TestUtil {
    static <T> UnaryBlockingCall<T> successfulUnaryCall(T result) {
        return new UnaryBlockingCall<T>() {
            @Override
            public ResponseMessage<T> execute() {
                return new ResponseMessage.Success<>(result, Collections.emptyMap(), Collections.emptyMap());
            }

            @Override
            public void cancel() {
                // in tests we don't need to preserve server resources, so no-op
            }
        };
    }

    public static X509Certificate createTestCertificate(PublicKey publicKey, PrivateKey privateKey) throws Exception {
        X500Name owner = new X500Name("CN=Test");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                owner,
                BigInteger.ONE,
                new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24),
                new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365)),
                owner,
                publicKey
        );

        return new JcaX509CertificateConverter().getCertificate(builder.build(new JcaContentSignerBuilder("SHA256WithRSA").build(privateKey)));
    }
}
