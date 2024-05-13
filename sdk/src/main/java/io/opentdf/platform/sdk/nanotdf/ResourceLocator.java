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
        return 1 + Integer.BYTES + this.body.length;
    }

    public byte[] writeIntoBuffer() {
        ByteBuffer buffer = ByteBuffer.allocate(getTotalSize());

        buffer.put((byte) this.protocol.ordinal());
        buffer.putInt(this.bodyLength);
        buffer.put(this.body);

        return buffer.array();
    }
}