package io.opentdf.platform.sdk.nanotdf;

import io.opentdf.platform.sdk.NanoTDF;

import java.nio.ByteBuffer;
import java.util.LinkedHashMap;
import java.util.Map;

public class CollectionStoreImpl extends LinkedHashMap<ByteBuffer, NanoTDF.CollectionKey>
        implements CollectionStore {
    private static final int MAX_SIZE_STORE = 500;

    public CollectionStoreImpl() {}

    public synchronized void store(Header header, NanoTDF.CollectionKey key) {
        ByteBuffer buf = ByteBuffer.allocate(header.getTotalSize());
        header.writeIntoBuffer(buf);
        super.put(buf, key);
    }

    public synchronized NanoTDF.CollectionKey getKey(Header header) {
        ByteBuffer buf = ByteBuffer.allocate(header.getTotalSize());
        header.writeIntoBuffer(buf);
        return super.getOrDefault(buf, NO_PRIVATE_KEY);
    }
    @Override
    protected boolean removeEldestEntry(Map.Entry<ByteBuffer, NanoTDF.CollectionKey> eldest) {
        return this.size() > MAX_SIZE_STORE;
    }
}
