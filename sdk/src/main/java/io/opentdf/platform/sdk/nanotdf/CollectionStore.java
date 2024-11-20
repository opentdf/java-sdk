package io.opentdf.platform.sdk.nanotdf;

import io.opentdf.platform.sdk.NanoTDF;

public interface CollectionStore {
    public static final NanoTDF.CollectionKey NO_PRIVATE_KEY = new NanoTDF.CollectionKey(null);
    void store(Header header, NanoTDF.CollectionKey key);
    NanoTDF.CollectionKey getKey(Header header);
}
