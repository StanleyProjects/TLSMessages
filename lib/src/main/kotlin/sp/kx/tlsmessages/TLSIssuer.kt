package sp.kx.tlsmessages

import java.util.Objects
import java.util.UUID
import javax.crypto.SecretKey

class TLSIssuer(
    val id: UUID,
    val method: Int,
    val query: ByteArray,
    val key: SecretKey,
) {
    override fun toString(): String {
        return "TLSIssuer($id)"
    }

    override fun equals(other: Any?): Boolean {
        return when (other) {
            is TLSIssuer -> {
                id == other.id &&
                    method == other.method &&
                    query.contentEquals(other.query) &&
                    key.encoded.contentEquals(other.key.encoded)
            }
            else -> false
        }
    }

    override fun hashCode(): Int {
        return Objects.hash(
            id,
            method,
            query.contentHashCode(),
            key.encoded.contentHashCode(),
        )
    }

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
