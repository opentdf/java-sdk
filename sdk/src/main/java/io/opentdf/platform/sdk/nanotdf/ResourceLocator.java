package io.opentdf.platform.sdk.nanotdf;

import java.nio.ByteBuffer;
import java.util.Arrays;
import org.checkerframework.checker.signature.qual.Identifier;

public class ResourceLocator {
    private NanoTDFType.Protocol protocol;
    private int bodyLength;
    private byte[] body;
    private NanoTDFType.IdentifierType identifierType;
    private int identiferLength;
    private byte[] identifer;

    public ResourceLocator() {
    }

    public ResourceLocator(String resourceUrl) {
        new ResourceLocator(resourceUrl, null);
    }

    public ResourceLocator(String resourceUrl, String identifier) {
        if (resourceUrl.startsWith("http://")) {
            this.protocol = NanoTDFType.Protocol.HTTP;
        } else if (resourceUrl.startsWith("https://")) {
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
            this.identiferLength = 0;
            this.identifer = new byte[0];
        } else {
            this.identifer = identifier.getBytes();
            int identifierLength = this.identifer.length;
            switch (identifierLength) {
                case 0:
                    this.identifierType = NanoTDFType.IdentifierType.NONE;
                    this.identiferLength = 0;
                    this.identifer = new byte[identiferLength];
                    break;
                case 2:
                    this.identifierType = NanoTDFType.IdentifierType.TWO_BYTES;
                    this.identiferLength = 2;
                    this.identifer = new byte[identiferLength];
                    break;
                case 8:
                    this.identifierType = NanoTDFType.IdentifierType.EIGHT_BYTES;
                    this.identiferLength = 8;
                    this.identifer = new byte[identiferLength];
                    break;
                case 32:
                    this.identifierType = NanoTDFType.IdentifierType.THIRTY_TWO_BYTES;
                    this.identiferLength = 32;
                    this.identifer = new byte[identiferLength];
                    break;
                default:
                    throw new IllegalArgumentException("Invalid identifier length: " + identifierLength);
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
                this.identiferLength = 0;
                this.identifer = new byte[identiferLength];
                break;
            case TWO_BYTES:
                this.identiferLength = 2;
                this.identifer = new byte[identiferLength];
                buffer.get(this.identifer);
                break;
            case EIGHT_BYTES:
                this.identiferLength = 8;
                this.identifer = new byte[identiferLength];
                buffer.get(this.identifer);
                break;
            case THIRTY_TWO_BYTES:
                this.identiferLength = 32;
                this.identifer = new byte[identiferLength];
                buffer.get(this.identifer);
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
           throw new RuntimeException("Failed to write resource locator - invalid buffer size.");
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