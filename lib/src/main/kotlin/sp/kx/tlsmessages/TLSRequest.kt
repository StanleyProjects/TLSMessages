package sp.kx.tlsmessages

import kotlin.time.Duration

sealed interface TLSRequest {
    class Encoded(
        val issuer: TLSIssuer,
        val bytes: ByteArray,
    ) : TLSRequest

    class Decoded(
        val issuer: TLSIssuer,
        @Deprecated("useless")
        val time: Duration,
        val body: ByteArray,
    ) : TLSRequest

    companion object {
        internal fun getMethodCode(method: String): Int {
            return when (method) {
                "POST" -> 1
                else -> error("Method \"${method}\" is not supported!")
            }
        }
    }
}
