package io.opentdf.platform.sdk;

import io.grpc.ManagedChannel;
import io.opentdf.platform.policy.attributes.GetAttributeValuesByFqnsRequest;
import io.opentdf.platform.policy.attributes.AttributesServiceGrpc;
import io.opentdf.platform.policy.attributes.GetAttributeValuesByFqnsResponse;


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
        this.channel.shutdownNow();
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
