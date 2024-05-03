package io.opentdf.platform.sdk;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.URI;
import java.util.Optional;

public interface TokenSource {
    class AuthTokens {
        private final String accessToken;
        private final String dpopProof;

        @Nonnull
        String getAccessToken() {
            return accessToken;
        }

        @Nonnull
        String getDpopProof() {
            return dpopProof;
        }
        AuthTokens(String accessToken, String dpopProof) {
            if (accessToken == null) {
                throw new NullPointerException("must specify access token");
            }
            if (dpopProof == null) {
                throw new NullPointerException("must specify dpop proof");
            }

            this.accessToken = accessToken;
            this.dpopProof = dpopProof;
        }
    }
    AuthTokens getAuthTokens(String method, URI resource);
}
