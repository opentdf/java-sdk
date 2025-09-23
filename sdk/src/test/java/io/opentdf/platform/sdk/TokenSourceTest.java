package io.opentdf.platform.sdk;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.oauth2.sdk.dpop.DefaultDPoPProofFactory;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

import static org.assertj.core.api.Assertions.assertThat;

class TokenSourceTest {

    @Test
    void getDPoPProof() throws URISyntaxException, JOSEException, MalformedURLException, ParseException {
        var fakeToken = new BearerAccessToken("this is a fake token");
        var keypair = CryptoUtils.generateRSAKeypair();
        var dpopKey = new RSAKey.Builder((RSAPublicKey) keypair.getPublic()).privateKey(keypair.getPrivate()).build();
        var dpopProofFactory = new DefaultDPoPProofFactory(dpopKey, JWSAlgorithm.RS256);

        var dpop = TokenSource.getDPoPProof(new URI("http://example.org/path/to/the/resource").toURL(), "POST", dpopProofFactory, fakeToken);

        var jws = JWSObject.parse(dpop);
        assertThat(jws.getPayload().toJSONObject())
                .extracting("htu")
                .containsOnly("/path/to/the/resource");
    }
}