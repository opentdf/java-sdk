package io.opentdf.platform.sdk;

import io.grpc.Channel;
import io.opentdf.platform.kas.AccessServiceGrpc;
import io.opentdf.platform.kas.PublicKeyRequest;
import io.opentdf.platform.kas.RewrapRequest;

import java.util.HashMap;
import java.util.function.Function;

public class KASClient implements SDK.KAS {

    private final Function<Config.KASInfo, Channel> channelFactory;

    public KASClient(Function <Config.KASInfo, Channel> channelFactory) {
        this.channelFactory = channelFactory;
    }

    @Override
    public String getPublicKey(Config.KASInfo kasInfo) {
        return getStub(kasInfo)
                .publicKey(PublicKeyRequest.getDefaultInstance())
                .getPublicKey();
    }

    @Override
    public byte[] unwrap(Config.KASInfo kasInfo, String policy, byte[] wrapped) {
        // this is obviously wrong. we still have to generate a correct request and decrypt the payload
        return getStub(kasInfo)
                .rewrap(RewrapRequest.getDefaultInstance())
                .getEntityWrappedKey()
                .toByteArray();
    }

    private final HashMap<Config.KASInfo, AccessServiceGrpc.AccessServiceBlockingStub> stubs = new HashMap<>();

    private synchronized AccessServiceGrpc.AccessServiceBlockingStub getStub(Config.KASInfo kasInfo) {
        if (!stubs.containsKey(kasInfo)) {
            var channel = channelFactory.apply(kasInfo);
            var stub = AccessServiceGrpc.newBlockingStub(channel);
            stubs.put(kasInfo, stub);
        }

        return stubs.get(kasInfo);
    }
}
