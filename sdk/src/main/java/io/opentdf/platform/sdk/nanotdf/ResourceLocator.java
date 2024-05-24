package io.opentdf.platform.sdk.nanotdf;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class ResourceLocator {
    private Protocol protocol;
    private int bodyLength;
    private byte[] body;

    public ResourceLocator() {
    }

    public ResourceLocator(String resourceUrl) {
        if (resourceUrl.startsWith("http://")) {
            this.protocol = Protocol.HTTP;
        } else if (resourceUrl.startsWith("https://")) {
            this.protocol = Protocol.HTTPS;
        } else {
            throw new RuntimeException("Unsupported protocol for resource locator");
        }

        this.body = resourceUrl.substring(resourceUrl.indexOf("://") + 3).getBytes();
        this.bodyLength = this.body.length;
    }

    public ResourceLocator(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);

        this.protocol = Protocol.values()[buffer.get()];
        this.bodyLength = buffer.getInt();
        this.body = new byte[this.bodyLength];
        buffer.get(this.body);
    }

    public void setProtocol(Protocol protocol) {
        this.protocol = protocol;
    }

    public void setBodyLength(int bodyLength) {
        this.bodyLength = bodyLength;
    }

    public void setBody(byte[] body) {
        this.body = body;
    }

    public String getResourceUrl() {
        StringBuilder sb = new StringBuilder();

        switch (this.protocol) {
            case HTTP:
                sb.append("http://");
                break;
            case HTTPS:
                sb.append("https://");
                break;
        }

        sb.append(new String(this.body));

        return sb.toString();
    }

    public int getTotalSize() {
        return 1 + 1 + this.body.length;
    }

    public int writeIntoBuffer(ByteBuffer buffer) {
        int totalSize = getTotalSize();
        if (buffer.remaining() < totalSize) {
           // throw new RuntimeException("Failed to write resource locator - invalid buffer size.");
            buffer = ByteBuffer.allocate(totalSize);
        }

        int totalBytesWritten = 0;

        // Write the protocol type.
        buffer.put((byte) protocol.ordinal());
        totalBytesWritten += 1; // size of byte

        // Write the url body length;
        buffer.put((byte)bodyLength);
        totalBytesWritten += 1;

        // Write the url body;
        buffer.put(body);
        totalBytesWritten += body.length;

        return totalBytesWritten;
    }
}