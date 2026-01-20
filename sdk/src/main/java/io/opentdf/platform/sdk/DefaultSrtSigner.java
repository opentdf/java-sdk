package io.opentdf.platform.sdk;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;

final class DefaultSrtSigner implements SrtSigner {
    private static final JWSHeader HEADER = new JWSHeader.Builder(JWSAlgorithm.RS256).build();
    private final RSASSASigner signer;

    DefaultSrtSigner(RSAKey rsaKey) {
        try {
            this.signer = new RSASSASigner(rsaKey);
        } catch (JOSEException e) {
            throw new SDKException("error creating SRT signer", e);
        }
    }

    @Override
    public byte[] sign(byte[] input) throws Exception {
        return signer.sign(HEADER, input).decode();
    }

    @Override
    public String alg() {
        return JWSAlgorithm.RS256.getName();
    }
}
