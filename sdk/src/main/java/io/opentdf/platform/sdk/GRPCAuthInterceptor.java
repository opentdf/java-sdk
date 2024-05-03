package io.opentdf.platform.sdk;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory;
import com.nimbusds.oauth2.sdk.dpop.DefaultDPoPProofFactory;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.tokenexchange.TokenExchangeGrant;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.ForwardingClientCall;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;

/**
 * The GRPCAuthInterceptor class is responsible for intercepting client calls before they are sent
 * to the server. It adds authentication headers to the requests by fetching and caching access
 * tokens.
 */
class GRPCAuthInterceptor implements ClientInterceptor {

    final TokenSource tokenSource;
    public GRPCAuthInterceptor(TokenSource tokenSource) {
        this.tokenSource = tokenSource;
    }

    @Override
    public <ReqT, RespT> ClientCall<ReqT, RespT> interceptCall(MethodDescriptor<ReqT, RespT> method,
                                                               CallOptions callOptions, Channel next) {
        return new ForwardingClientCall.SimpleForwardingClientCall<>(next.newCall(method, callOptions)) {
            @Override
            public void start(Listener<RespT> responseListener, Metadata headers) {
                // Get the access token
                URI resource;
                try {
                    resource = new URI("/" + method.getFullMethodName());
                } catch (URISyntaxException e) {
                    throw new RuntimeException("Invalid URI syntax for DPoP proof creation");
                }

                var authTokens = tokenSource.getAuthTokens("POST", resource);
                headers.put(Metadata.Key.of("Authorization", Metadata.ASCII_STRING_MARSHALLER),
                        "DPoP " + authTokens.getAccessToken());
                headers.put(Metadata.Key.of("DPoP", Metadata.ASCII_STRING_MARSHALLER),
                        authTokens.getDpopProof());

                super.start(responseListener, headers);
            }
        };
    }

}
