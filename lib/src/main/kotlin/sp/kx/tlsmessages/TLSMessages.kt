package sp.kx.tlsmessages

import java.security.KeyPair

interface TLSMessages {
    fun toRequest(
        keyPair: KeyPair,
        method: String,
        query: String,
        body: ByteArray,
    ): TLSRequest

    fun fromRequest(
        keyPair: KeyPair,
        method: String,
        query: String,
        bytes: ByteArray,
    ): TLSRequest.Decoded
}
