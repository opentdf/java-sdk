package io.opentdf.platform.sdk.nanotdf;

import io.opentdf.platform.sdk.NanoTDF;

public interface CollectionStore {
    NanoTDF.CollectionKey NO_PRIVATE_KEY = new NanoTDF.CollectionKey(null);
    void store(Header header, NanoTDF.CollectionKey key);
    NanoTDF.CollectionKey getKey(Header header);

    class NoOpCollectionStore implements CollectionStore {
        public NoOpCollectionStore() {}

        @Override
        public void store(Header header, NanoTDF.CollectionKey key) {}

        @Override
        public NanoTDF.CollectionKey getKey(Header header) {
            return NO_PRIVATE_KEY;
        }
    }
}
