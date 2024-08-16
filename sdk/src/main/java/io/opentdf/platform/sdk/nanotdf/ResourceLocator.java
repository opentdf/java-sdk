package io.opentdf.platform.sdk.nanotdf;

import java.nio.ByteBuffer;
import java.util.Objects;

/**
 * The ResourceLocator class represents a resource locator containing a
 * protocol, body, and identifier. It provides methods to set and retrieve
 * the protocol, body, and identifier, as well as to get the resource URL and
 * the total size of the resource locator. It also provides methods to write
 * the resource locator into a ByteBuffer and obtain the identifier.
 */
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

    public ResourceLocator(final String resourceUrl) {
        this(resourceUrl, null);
    }

    /**
     * ResourceLocator represents a locator for a resource.
     * It takes a resource URL and an identifier as parameters and initializes the object.
     * The resource URL is used to determine the protocol and the body.
     * The identifier is used to determine the identifier type and the identifier value.
     *
     * @param resourceUrl the URL of the resource
     * @param identifier the identifier of the resource (optional, can be null)
     * @throws IllegalArgumentException if the resource URL has an unsupported protocol or if the identifier length is unsupported
     */
    public ResourceLocator(final String resourceUrl, final String identifier) {
        if (resourceUrl.startsWith(HTTP)) {
            this.protocol = NanoTDFType.Protocol.HTTP;
        } else if (resourceUrl.startsWith(HTTPS)) {
            this.protocol = NanoTDFType.Protocol.HTTPS;
        } else {
            throw new IllegalArgumentException("Unsupported protocol for resource locator");
        }
        // body
        this.body = resourceUrl.substring(resourceUrl.indexOf("://") + 3).getBytes();
        this.bodyLength = this.body.length;
        // identifier
        if (identifier == null) {
            this.identifierType = NanoTDFType.IdentifierType.NONE;
            this.identifier = new byte[NanoTDFType.IdentifierType.NONE.getLength()];
        } else {
            int identifierLen = identifier.getBytes().length;
            if (identifierLen == 0) {
                this.identifierType = NanoTDFType.IdentifierType.NONE;
                this.identifier = new byte[NanoTDFType.IdentifierType.NONE.getLength()];
            } else if (identifierLen <= 2) {
                this.identifierType = NanoTDFType.IdentifierType.TWO_BYTES;
                this.identifier = new byte[NanoTDFType.IdentifierType.TWO_BYTES.getLength()];
                System.arraycopy(identifier.getBytes(), 0, this.identifier, 0, identifierLen);
            } else if (identifierLen <= 8) {
                this.identifierType = NanoTDFType.IdentifierType.EIGHT_BYTES;
                this.identifier = new byte[NanoTDFType.IdentifierType.EIGHT_BYTES.getLength()];
                System.arraycopy(identifier.getBytes(), 0, this.identifier, 0, identifierLen);
            } else if (identifierLen <= 32) {
                this.identifierType = NanoTDFType.IdentifierType.THIRTY_TWO_BYTES;
                this.identifier = new byte[NanoTDFType.IdentifierType.THIRTY_TWO_BYTES.getLength()];
                System.arraycopy(identifier.getBytes(), 0, this.identifier, 0, identifierLen);
            } else {
                throw new IllegalArgumentException("Unsupported identifier length: " + identifierLen);
            }
        }
    }

    public ResourceLocator(ByteBuffer buffer) {
        // Get the first byte and mask it with 0xF to keep only the first four bits
        final byte protocolWithIdentifier = buffer.get();
        int protocolNibble = protocolWithIdentifier & 0x0F;
        int identifierNibble = (protocolWithIdentifier & 0xF0) >> 4;
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

    public void setIdentifier(String identifier) {
        if (identifier == null) {
            this.identifierType = NanoTDFType.IdentifierType.NONE;
            this.identifier = new byte[0];
        } else {
            byte[] identifierBytes = identifier.getBytes();
            int identifierLen = identifierBytes.length;

            if (identifierLen == 0) {
                this.identifierType = NanoTDFType.IdentifierType.NONE;
                this.identifier = new byte[0];
            } else if (identifierLen <= 2) {
                this.identifierType = NanoTDFType.IdentifierType.TWO_BYTES;
                this.identifier = new byte[2];
                System.arraycopy(identifierBytes, 0, this.identifier, 0, identifierLen);
            } else if (identifierLen <= 8) {
                this.identifierType = NanoTDFType.IdentifierType.EIGHT_BYTES;
                this.identifier = new byte[8];
                System.arraycopy(identifierBytes, 0, this.identifier, 0, identifierLen);
            } else if (identifierLen <= 32) {
                this.identifierType = NanoTDFType.IdentifierType.THIRTY_TWO_BYTES;
                this.identifier = new byte[32];
                System.arraycopy(identifierBytes, 0, this.identifier, 0, identifierLen);
            } else {
                throw new IllegalArgumentException("Unsupported identifier length: " + identifierLen);
            }
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

    /**
     * Writes the resource locator into the provided ByteBuffer.
     *
     * @param buffer the ByteBuffer to write into
     * @return the number of bytes written
     * @throws RuntimeException if the buffer size is insufficient to write the resource locator
     */
    public int writeIntoBuffer(ByteBuffer buffer) {
        int totalSize = getTotalSize();
        if (buffer.remaining() < totalSize) {
           throw new RuntimeException("Failed to write resource locator - invalid buffer size.");
        }

        int totalBytesWritten = 0;

        // Write the protocol type.
        if (identifierType == NanoTDFType.IdentifierType.NONE) {
            buffer.put((byte) protocol.ordinal());
            totalBytesWritten += 1; // size of byte
        } else {
            buffer.put((byte) (identifierType.ordinal() << 4 | protocol.ordinal()));
            totalBytesWritten += 1;
        }

        // Write the url body length
        buffer.put((byte)bodyLength);
        totalBytesWritten += 1;

        // Write the url body
        buffer.put(body);
        totalBytesWritten += body.length;

        // Write the identifier
        if (identifierType != NanoTDFType.IdentifierType.NONE) {
            buffer.put(identifier);
            totalBytesWritten += identifier.length;
        }

        return totalBytesWritten;
    }

    public byte[] getIdentifier() {
        return this.identifier;
    }

    // getIdentifierString removes potential padding
    public String getIdentifierString() {
            int actualLength = 0;
            for (int i = 0; i < this.identifier.length; i++) {
                if (this.identifier[i] != 0) {
                    actualLength = i + 1;
                }
            }
            return new String(this.identifier, 0, actualLength);
    }
}