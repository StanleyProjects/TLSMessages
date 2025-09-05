package sp.kx.tlsmessages

class TLSRequest(
    val issuer: TLSIssuer,
    val body: ByteArray,
) {
    companion object {
        internal fun getMethodCode(method: String): Byte {
            return when (method) {
                "POST" -> 1
                else -> error("Method \"${method}\" is not supported!")
            }
        }
    }
}
