package io.opentdf.platform.sdk;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;

import static java.lang.String.format;

class AddressNormalizer {
    private static final Logger logger = LoggerFactory.getLogger(AddressNormalizer.class);

    private AddressNormalizer(){
    }

    static String normalizeAddress(String urlString, boolean usePlaintext) {
        final String scheme = usePlaintext ? "http" : "https";
        URI uri = getInitialUri(urlString);

        if (uri.getHost() == null) {
            // if there is no host and no scheme, then we assume the input is a hostname with no port or scheme
            if (uri.getScheme() == null) {
                try {
                    uri = new URI(scheme, null, uri.getSchemeSpecificPart(), -1, null, null, null);
                } catch (URISyntaxException e) {
                    throw new SDKException("error trying to create URL for hostname [" + urlString + "]", e);
                }
            } else {
                // otherwise, we have a scheme but no host, so we assume the scheme is actually the host and the SSP is the port
                try {
                    uri = new URI(scheme, null, uri.getScheme(), Integer.parseInt(uri.getSchemeSpecificPart()), null, null, null);
                } catch (URISyntaxException | NumberFormatException e) {
                    throw new SDKException("error trying to create URL for host and port[" + urlString + "]", e);
                }
            }
        }
        final int port;
        if (uri.getPort() == -1) {
            port = usePlaintext ? 80 : 443;
        } else {
            port = uri.getPort();
        }

        try {
            var returnUrl = new URI(scheme, null, uri.getHost(), port, null, null, null).toString();
            logger.debug("normalized url [{}] to [{}]", urlString, returnUrl);
            return returnUrl;
        } catch (URISyntaxException e) {
            throw new SDKException("error creating KAS address", e);
        }
    }

    // tries to parse a URI that is possibly missing a scheme by first trying the input directly, and then
    // trying again with a fake scheme if the first attempt fails. this is needed because URIs without a schema
    // whose hostnames are not valid schemas will fail to parse
    private static URI getInitialUri(String urlString) {
        URISyntaxException initialThrown = null;
        try {
            return new URI(urlString);
        } catch (URISyntaxException e) {
            // this can happen if there is no schema and the hostname is not a valid scheme, like if we havea
            // an IP adddress
            initialThrown = e;
        }

        try {
            return new URI(format("fake://%s", urlString));
        } catch (URISyntaxException e) {
            throw new SDKException("error parsing url [" + urlString + "]", initialThrown);
        }
    }
}
