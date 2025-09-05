package sp.kx.tlsmessages

import java.util.UUID
import kotlin.time.Duration

class TLSPayload(
    val id: UUID,
    val time: Duration,
    val bytes: ByteArray,
)
