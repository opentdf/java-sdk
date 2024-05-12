package io.opentdf.platform.sdk;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class TDFReader {

    public TDFReader(InputStream inputStream) {
    }

    public String manifest()  {
        return "Not Implemented";
    }

    public byte[] readPayload(long index, long length) {
        byte[] data = new byte[0];
        return data;
    }

    public long PayloadSize() {
        return 0;
    }
}
