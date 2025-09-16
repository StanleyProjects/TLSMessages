package sp.kx.tlsmessages

import sp.kx.bytes.writeBytes
import java.io.ByteArrayOutputStream
import java.util.UUID
import kotlin.time.Duration

internal object TLSBytes {
    const val ivSize = 16

    fun toPayload(
        id: UUID,
        time: Duration,
        body: ByteArray,
    ): ByteArray {
        return ByteArrayOutputStream().use {
            it.writeBytes(value = id)
            it.writeBytes(value = time.inWholeMilliseconds)
            it.writeBytes(value = body.size)
            it.writeBytes(body)
            it.toByteArray()
        }
    }

    fun toSignee(
        issuer: TLSIssuer,
        time: Duration,
        body: ByteArray,
    ): ByteArray {
        return ByteArrayOutputStream().use {
            it.writeBytes(value = issuer.id)
            it.write(issuer.method)
            it.writeBytes(issuer.query)
            it.writeBytes(issuer.key.encoded)
            it.writeBytes(body)
            it.writeBytes(value = time.inWholeMilliseconds)
            it.toByteArray()
        }
    }

    fun toSignee(
        issuer: TLSIssuer,
        payload: ByteArray,
        code: Int,
        message: String,
    ): ByteArray {
        return ByteArrayOutputStream().use {
            it.writeBytes(value = issuer.id)
            it.write(issuer.method)
            it.writeBytes(issuer.query)
            it.writeBytes(issuer.key.encoded)
            it.writeBytes(payload)
            it.writeBytes(value = code)
            it.writeBytes(message.toByteArray())
            it.toByteArray()
        }
    }
}
