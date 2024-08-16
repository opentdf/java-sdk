package io.opentdf.platform.sdk;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.function.Function;

import io.grpc.ManagedChannel;
import io.opentdf.platform.policy.attributes.GetAttributeValuesByFqnsRequest;
import io.opentdf.platform.policy.attributes.AttributesServiceGrpc;
import io.opentdf.platform.policy.attributes.GetAttributeValuesByFqnsResponse;

import static java.lang.String.format;


public class AttributesClient implements SDK.AttributesService {

    private final ManagedChannel channel;

    /***
     * A client that communicates with KAS
     * @param channelFactory A function that produces channels that can be used to communicate
     * @param dpopKey
     */
    public AttributesClient(ManagedChannel channel) {
        this.channel = channel;
    }


    @Override
    public synchronized void close() {
        var entries = new ArrayList<>(stubs.values());
        stubs.clear();
        for (var entry: entries) {
            entry.channel.shutdownNow();
        }
    }

    private String normalizeAddress(String urlString) {
        URL url;
        try {
            url = new URL(urlString);
        } catch (MalformedURLException e) {
            // if there is no protocol then they either gave us
            // a correct address or one we don't know how to fix
            return urlString;
        }

        // otherwise we take the specified port or default
        // based on whether the URL uses a scheme that
        // implies TLS
        int port;
        if (url.getPort() == -1) {
            if ("http".equals(url.getProtocol())) {
                port = 80;
            } else {
                port = 443;
            }
        } else {
            port = url.getPort();
        }

        return format("%s:%d", url.getHost(), port);
    }


    private final HashMap<String, CacheEntry> stubs = new HashMap<>();
    private static class CacheEntry {
        final ManagedChannel channel;
        final AttributesServiceGrpc.AttributesServiceBlockingStub stub;
        private CacheEntry(ManagedChannel channel, AttributesServiceGrpc.AttributesServiceBlockingStub stub) {
            this.channel = channel;
            this.stub = stub;
        }
    }

    // make this protected so we can test the address normalization logic
    synchronized AttributesServiceGrpc.AttributesServiceBlockingStub getStub() {
        return AttributesServiceGrpc.newBlockingStub(channel);
    }


    @Override
    public GetAttributeValuesByFqnsResponse getAttributeValuesByFqn(GetAttributeValuesByFqnsRequest request) {
        return getStub().getAttributeValuesByFqns(request);
    } 

}
