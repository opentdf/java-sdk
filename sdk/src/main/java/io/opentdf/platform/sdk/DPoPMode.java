package io.opentdf.platform.sdk;

/**
 * Selects the {@code htu} form of DPoP proofs sent to platform services and KAS. Both forms use
 * the {@code DPoP} Authorization scheme, and token endpoint proofs always use the full URL.
 * Plain Bearer tokens (an AS that did not bind the token to the DPoP key) are unaffected
 * and are always sent as {@code Authorization: Bearer} without a proof.
 */
public enum DPoPMode {
    /**
     * Discover the style once per server origin from what the server advertises: the
     * {@code dpop} block or {@code dpop_signing_alg_values_supported} in
     * {@code /.well-known/opentdf-configuration}, then RFC 9728
     * {@code /.well-known/oauth-protected-resource}. Servers that advertise neither get
     * {@link #LEGACY}; a discovery that gets no answer uses legacy for that request and is retried.
     * This is the default.
     */
    AUTO,
    /**
     * Pre-RFC 9449 form the first DPoP platforms (service v0.11.x) require: an RPC's {@code htu}
     * is its procedure ({@code /package.Service/Method}); other requests keep the full URL.
     */
    LEGACY,
    /**
     * RFC 9449 form: the {@code htu} is the full request URL without query or fragment.
     */
    RFC9449
}
