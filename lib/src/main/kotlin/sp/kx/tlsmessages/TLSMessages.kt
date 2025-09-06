package sp.kx.tlsmessages

import java.security.KeyPair

interface TLSMessages {
    fun toRequest(
        keyPair: KeyPair,
        method: String,
        query: String,
        body: ByteArray,
    ): TLSRequest.Encoded

    fun fromRequest(
        keyPair: KeyPair,
        method: String,
        query: String,
        bytes: ByteArray,
    ): TLSRequest.Decoded

    fun toResponseBody(
        keyPair: KeyPair,
        code: Int,
        message: String,
        body: ByteArray?,
        issuer: TLSIssuer,
    ): ByteArray

    fun fromResponseBody(
        keyPair: KeyPair,
        code: Int,
        message: String,
        issuer: TLSIssuer,
        bytes: ByteArray,
    ): ByteArray
}
