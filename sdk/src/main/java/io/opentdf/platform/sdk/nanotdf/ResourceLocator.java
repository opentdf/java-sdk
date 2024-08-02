package io.opentdf.platform.sdk.nanotdf;

import java.nio.ByteBuffer;
import java.util.Objects;

public class ResourceLocator {
    private static final String HTTP = "http://";
    private static final String HTTPS = "https://";

    private NanoTDFType.Protocol protocol;
    private int bodyLength;
    private byte[] body;
    private NanoTDFType.IdentifierType identifierType;
    private byte[] identifier;

    public ResourceLocator() {
    }

    public ResourceLocator(String resourceUrl) {
        new ResourceLocator(resourceUrl, null);
    }

    public ResourceLocator(String resourceUrl, String identifier) {
        if (resourceUrl.startsWith(HTTP)) {
            this.protocol = NanoTDFType.Protocol.HTTP;
        } else if (resourceUrl.startsWith(HTTPS)) {
            this.protocol = NanoTDFType.Protocol.HTTPS;
        } else {
            throw new RuntimeException("Unsupported protocol for resource locator");
        }
        // body
        this.body = resourceUrl.substring(resourceUrl.indexOf("://") + 3).getBytes();
        this.bodyLength = this.body.length;
        // identifier
        if (identifier == null) {
            this.identifierType = NanoTDFType.IdentifierType.NONE;
            this.identifier = new byte[0];
        } else {
            this.identifier = identifier.getBytes();
            switch (this.identifier.length) {
                case 0:
                case 2:
                case 8:
                case 32:
                    this.identifierType = NanoTDFType.IdentifierType.values()[this.identifier.length / 8];
                    break;
                default:
                    throw new IllegalArgumentException("Invalid identifier length: " + this.identifier.length);
            }
        }
    }

    public ResourceLocator(ByteBuffer buffer) {
        final byte protocolWithIdentifier = buffer.get();
        int protocolNibble = (protocolWithIdentifier & 0xF0) >> 4;
        int identifierNibble = protocolWithIdentifier & 0x0F;
        this.protocol = NanoTDFType.Protocol.values()[protocolNibble];
        // body
        this.bodyLength = buffer.get();
        this.body = new byte[this.bodyLength];
        buffer.get(this.body);
        // identifier
        this.identifierType = NanoTDFType.IdentifierType.values()[identifierNibble];
        switch (this.identifierType) {
            case NONE:
                this.identifier = new byte[0];
                break;
            case TWO_BYTES:
                this.identifier = new byte[2];
                buffer.get(this.identifier);
                break;
            case EIGHT_BYTES:
                this.identifier = new byte[8];
                buffer.get(this.identifier);
                break;
            case THIRTY_TWO_BYTES:
                this.identifier = new byte[32];
                buffer.get(this.identifier);
                break;
            default:
                throw new IllegalArgumentException("Unexpected identifier type: " + identifierType);
        }
    }

    public void setProtocol(NanoTDFType.Protocol protocol) {
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

        if (Objects.requireNonNull(this.protocol) == NanoTDFType.Protocol.HTTP) {
            sb.append(HTTP);
        } else if (this.protocol == NanoTDFType.Protocol.HTTPS) {
            sb.append(HTTPS);
        }

        sb.append(new String(this.body));

        return sb.toString();
    }

    public int getTotalSize() {
        return 1 + 1 + this.body.length + this.identifier.length;
    }

    public int writeIntoBuffer(ByteBuffer buffer) {
        int totalSize = getTotalSize();
        if (buffer.remaining() < totalSize) {
           throw new RuntimeException("Failed to write resource locator - invalid buffer size.");
        }

        int totalBytesWritten = 0;

        // Write the protocol type.
        buffer.put((byte) protocol.ordinal());
        totalBytesWritten += 1; // size of byte

        // Write the url body length
        buffer.put((byte)bodyLength);
        totalBytesWritten += 1;

        // Write the url body
        buffer.put(body);
        totalBytesWritten += body.length;

        return totalBytesWritten;
    }
}