package sp.kx.tlsmessages

import java.util.UUID
import javax.crypto.SecretKey

class TLSIssuer(
    val method: Int,
    val query: ByteArray,
    val key: SecretKey,
    val id: UUID,
) {
    companion object {
        fun of(
            method: String,
            query: String,
            key: SecretKey,
            id: UUID,
        ): TLSIssuer {
            return TLSIssuer(
                method = TLSRequest.getMethodCode(method = method),
                query = query.toByteArray(),
                key = key,
                id = id,
            )
        }
    }
}
