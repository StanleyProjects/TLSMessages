package sp.kx.tlsmessages

interface TLSReceiver {
    fun fromRequest(
        method: String,
        query: String,
        bytes: ByteArray,
    ): TLSRequest.Decoded

    fun toResponseBody(
        code: Int,
        message: String,
        body: ByteArray?,
        issuer: TLSIssuer,
    ): ByteArray
}
