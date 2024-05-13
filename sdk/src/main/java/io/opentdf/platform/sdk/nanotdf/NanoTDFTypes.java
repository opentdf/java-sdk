package io.opentdf.platform.sdk.nanotdf;

enum EllipticCurve {
    SECP256R1,
    SECP384R1,
    SECP521R1,
    SECP256K1;
}

enum Protocol {
    HTTP,
    HTTPS
}

enum NanoTDFPolicyType {
    REMOTE_POLICY,
    EMBEDDED_POLICY_PLAIN_TEXT,
    EMBEDDED_POLICY_ENCRYPTED,
    EMBEDDED_POLICY_ENCRYPTED_POLICY_KEY_ACCESS
}

enum NanoTDFCipher{
    AES_256_GCM_64_TAG ,
    AES_256_GCM_96_TAG ,
    AES_256_GCM_104_TAG ,
    AES_256_GCM_112_TAG ,
    AES_256_GCM_120_TAG ,
    AES_256_GCM_128_TAG ,
    EAD_AES_256_HMAC_SHA_256
}
