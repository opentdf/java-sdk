package io.opentdf.platform.sdk;

import com.connectrpc.protocols.NetworkProtocol;

/**
 * Enumeration of supported network protocols for SDK communication.
 * 
 * This enum provides a mapping between SDK protocol types and the underlying
 * Connect-RPC NetworkProtocol values, allowing flexible configuration of the
 * communication protocol used for platform services.
 */
public enum ProtocolType {
    /**
     * Connect's native protocol - HTTP-based with support for HTTP/1.1, HTTP/2, and HTTP/3.
     * Supports both JSON and binary Protobuf encoding with streaming capabilities.
     * This is the recommended default for new applications.
     */
    CONNECT(NetworkProtocol.CONNECT),
    
    /**
     * Standard gRPC protocol - requires HTTP/2 and uses binary Protobuf encoding.
     * Provides full gRPC compatibility including streaming, trailers, and error details.
     */
    GRPC(NetworkProtocol.GRPC),
    
    /**
     * gRPC-Web protocol - designed for web browsers, works over HTTP/1.1 and HTTP/2.
     * Eliminates the need for a translating proxy like Envoy.
     */
    GRPC_WEB(NetworkProtocol.GRPC_WEB);
    
    private final NetworkProtocol networkProtocol;
    
    ProtocolType(NetworkProtocol networkProtocol) {
        this.networkProtocol = networkProtocol;
    }
    
    /**
     * Get the underlying Connect-RPC NetworkProtocol value.
     * 
     * @return the NetworkProtocol corresponding to this ProtocolType
     */
    public NetworkProtocol getNetworkProtocol() {
        return networkProtocol;
    }
}