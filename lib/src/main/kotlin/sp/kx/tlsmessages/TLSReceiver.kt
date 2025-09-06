package sp.kx.tlsmessages

import java.security.KeyPair

interface TLSReceiver {
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
}
