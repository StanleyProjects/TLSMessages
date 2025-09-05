package sp.kx.tlsmessages

import java.security.KeyPair

interface TLSMessages {
    fun toRequest(
        keyPair: KeyPair,
        method: String,
        query: String,
        bytes: ByteArray,
    ): TLSRequest

    fun fromResponse(
        issuer: TLSIssuer,
        body: ByteArray,
    ): ByteArray
}
