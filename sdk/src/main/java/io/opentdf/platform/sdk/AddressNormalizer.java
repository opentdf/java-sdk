package io.opentdf.platform.sdk;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

class AddressNormalizer {
    private static final Logger logger = LoggerFactory.getLogger(AddressNormalizer.class);

    private AddressNormalizer(){
    }

    static String normalizeAddress(String urlString, boolean usePlaintext) {
        URI uri;
        try {
            uri = new URI(urlString);
        } catch (URISyntaxException e) {
            throw new SDKException("error trying to parse URL [" + urlString + "]", e);
        }

        if (uri.getHost() == null) {
            // if there is no host then we are likely dealing with a host and port
            try {
                uri = new URI(usePlaintext ? "http" : "https", null, uri.getScheme(), Integer.parseInt(uri.getSchemeSpecificPart()), null, null, null);
            } catch (URISyntaxException e) {
                throw new SDKException("error trying to create URL for host and port[" + urlString + "]", e);
            }
        }
        final int port;
        if (uri.getPort() == -1) {
            port = usePlaintext ? 80 : 443;
        } else {
            port = uri.getPort();
        }
        final String scheme = usePlaintext ? "http" : "https";

        try {
            var returnUrl = new URI(scheme, null, uri.getHost(), port, null, null, null).toString();
            logger.debug("normalized url [{}] to [{}]", urlString, returnUrl);
            return returnUrl;
        } catch (URISyntaxException e) {
            throw new SDKException("error creating KAS address", e);
        }
    }

    private static URI tryParseHostAndPort(String urlString) {
        URI uri;
        try {
            uri = new URI(null, urlString, null, null, null).parseServerAuthority();
        } catch (URISyntaxException e) {
            throw new SDKException("error trying to parse host and port", e);
        }

        try {
            return new URI(uri.getPort() == 443 ? "https" : "http", null, uri.getHost(), uri.getPort(), "", "", "");
        } catch (URISyntaxException e) {
            throw new SDKException("error trying to create URL from host and port", e);
        }
    }
}
