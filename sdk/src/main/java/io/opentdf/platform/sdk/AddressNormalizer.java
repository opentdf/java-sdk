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
        URL url;
        try {
            url = new URL(urlString);
        } catch (MalformedURLException e) {
            url = tryParseHostAndPort(urlString);
        }
        final int port;
        if (url.getPort() == -1) {
            port = "http".equals(url.getProtocol()) ? 80 : 443;
        } else {
            port = url.getPort();
        }
        final String protocol = usePlaintext && "http".equals(url.getProtocol()) ? "http" : "https";

        try {
            var returnUrl = new URL(protocol, url.getHost(), port, "").toString();
            logger.debug("normalized url [{}] to [{}]", urlString, returnUrl);
            return returnUrl;
        } catch (MalformedURLException e) {
            throw new SDKException("error creating KAS address", e);
        }
    }

    private static URL tryParseHostAndPort(String urlString) {
        URI uri;
        try {
            uri = new URI(null, urlString, null, null, null).parseServerAuthority();
        } catch (URISyntaxException e) {
            throw new SDKException("error trying to parse host and port", e);
        }

        try {
            return new URL(uri.getPort() == 443 ? "https" : "http", uri.getHost(), uri.getPort(), "");
        } catch (MalformedURLException e) {
            throw new SDKException("error trying to create URL from host and port", e);
        }
    }
}
