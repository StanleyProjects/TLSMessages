package sp.kx.tlsmessages

import java.util.UUID
import javax.crypto.SecretKey

class TLSRequest internal constructor(
    val method: Byte,
    val query: ByteArray,
    val key: SecretKey,
    val id: UUID,
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
