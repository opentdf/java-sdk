package io.opentdf.platform.sdk;

import io.grpc.ManagedChannel;
import io.opentdf.platform.policy.attributes.GetAttributeValuesByFqnsRequest;
import io.opentdf.platform.policy.attributes.AttributesServiceGrpc;
import io.opentdf.platform.policy.attributes.GetAttributeValuesByFqnsResponse;


public class AttributesClient implements SDK.AttributesService {

    private final ManagedChannel channel;

    /***
     * A client that communicates with Attributes Service
    */
    public AttributesClient(ManagedChannel channel) {
        this.channel = channel;
    }


    @Override
    public synchronized void close() {
        this.channel.shutdownNow();
    }

    @Override
    public AttributesServiceGrpc.AttributesServiceBlockingStub getAttributesServiceBlockingStub() {
        return AttributesServiceGrpc.newBlockingStub(channel);
    }

    @Override
    public AttributesServiceGrpc.AttributesServiceStub getAttributesServiceStub() {
        return AttributesServiceGrpc.newStub(channel);
    }

    @Override
    public AttributesServiceGrpc.AttributesServiceFutureStub getAttributesServiceFutureStub() {
        return AttributesServiceGrpc.newFutureStub(channel);
    }
}
