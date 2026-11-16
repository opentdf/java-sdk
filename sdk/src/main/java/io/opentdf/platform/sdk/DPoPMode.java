package io.opentdf.platform.sdk;

/**
 * Selects the {@code htu} form of DPoP proofs sent to platform services and KAS. Both forms use
 * the {@code DPoP} Authorization scheme, and token endpoint proofs always use the full URL.
 * Plain Bearer tokens (an AS that did not bind the token to the DPoP key) are unaffected
 * and are always sent as {@code Authorization: Bearer} without a proof.
 */
public enum DPoPMode {
    /**
     * Discover the style per server origin from what the server advertises: the
     * {@code dpop} block or {@code dpop_signing_alg_values_supported} in the opentdf well-known
     * configuration ({@code WellKnownService/GetWellKnownConfiguration}), then RFC 9728
     * {@code /.well-known/oauth-protected-resource}. Servers that advertise neither get
     * {@link #LEGACY}. A discovery that gets no usable answer (a network error, timeout, redirect,
     * or a status other than 200, 404, 405 and 501) uses legacy for 30 seconds before the server is
     * asked again. Answers are cached per origin for a few minutes (see
     * {@link SDKBuilder#dpopDiscoveryCacheTtl}), then rediscovered, so a server that is upgraded or
     * reconfigured is picked up without restarting the client. This is the default.
     */
    AUTO,
    /**
     * Pre-RFC 9449 form that service releases before v0.18.0 require: an RPC's {@code htu} is its
     * procedure ({@code /package.Service/Method}).
     */
    LEGACY,
    /**
     * RFC 9449 form: the {@code htu} is the full request URL without query or fragment.
     */
    RFC9449
}
