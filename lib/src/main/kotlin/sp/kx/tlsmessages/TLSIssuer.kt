package sp.kx.tlsmessages

import java.util.UUID
import javax.crypto.SecretKey

class TLSIssuer(
    val method: Byte,
    val query: ByteArray,
    val key: SecretKey,
    val id: UUID,
)
