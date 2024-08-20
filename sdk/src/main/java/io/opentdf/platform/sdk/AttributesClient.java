package io.opentdf.platform.sdk;

import io.grpc.ManagedChannel;
import io.opentdf.platform.policy.attributes.AttributesServiceGrpc;

public class AttributesClient implements SDK.AttributesService {

    private final ManagedChannel channel;

    private AttributesServiceGrpc.AttributesServiceBlockingStub attributesServiceBlockingStub;
    private AttributesServiceGrpc.AttributesServiceStub attributesServiceStub;
    private AttributesServiceGrpc.AttributesServiceFutureStub attributesServiceFutureStub;

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
    public synchronized AttributesServiceGrpc.AttributesServiceBlockingStub getAttributesServiceBlockingStub() {
        if (attributesServiceBlockingStub==null){
            attributesServiceBlockingStub = AttributesServiceGrpc.newBlockingStub(channel);
        }
        return attributesServiceBlockingStub;
    }

    @Override
    public synchronized AttributesServiceGrpc.AttributesServiceStub getAttributesServiceStub() {
        if (attributesServiceStub==null){
            attributesServiceStub = AttributesServiceGrpc.newStub(channel);
        }
        return attributesServiceStub;
    }

    @Override
    public synchronized AttributesServiceGrpc.AttributesServiceFutureStub getAttributesServiceFutureStub() {
        if (attributesServiceFutureStub==null){
            attributesServiceFutureStub = AttributesServiceGrpc.newFutureStub(channel);
        }
        return attributesServiceFutureStub;
    }
}
