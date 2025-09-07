package sp.kx.tlsmessages

interface TLSTransmitter {
    fun toRequest(
        method: String,
        query: String,
        body: ByteArray,
    ): TLSRequest.Encoded

    fun fromResponseBody(
        code: Int,
        message: String,
        issuer: TLSIssuer,
        bytes: ByteArray,
    ): ByteArray
}
