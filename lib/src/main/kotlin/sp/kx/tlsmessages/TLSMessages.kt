package sp.kx.tlsmessages

import java.security.KeyPair

interface TLSMessages {
    fun request(
        keyPair: KeyPair,
        method: String,
        query: String,
        bytes: ByteArray,
    ): TLSRequest
}
