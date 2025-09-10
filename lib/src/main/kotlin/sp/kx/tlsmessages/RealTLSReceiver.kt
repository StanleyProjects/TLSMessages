package sp.kx.tlsmessages

import sp.kx.bytes.readBytes
import sp.kx.bytes.readInt
import sp.kx.bytes.readLong
import sp.kx.bytes.readUUID
import sp.kx.bytes.writeBytes
import sp.kx.secrets.Asymmetric
import sp.kx.secrets.Symmetric
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.KeyPair
import java.security.SecureRandom
import java.util.UUID
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes

class RealTLSReceiver(
    private val keyPair: KeyPair,
    private val symmetric: Symmetric,
    private val asymmetric: Asymmetric,
    private val requested: MutableMap<UUID, Duration>,
) : TLSReceiver {
    override fun fromRequest(
        method: String,
        query: String,
        bytes: ByteArray,
    ): TLSRequest.Decoded {
        val (key, payload, signature) = ByteArrayInputStream(bytes).use {
            val encryptedKey = it.readBytes(it.readInt())
            val encodedKey = asymmetric.enc.decrypt(keyPair.private, encryptedKey)
            val key = symmetric.factory.toSecretKey(encodedKey)
            val encrypted = it.readBytes(it.readInt())
            val iv = it.readBytes(TLSBytes.ivSize)
            val signature = it.readBytes(it.readInt())
            val payload = symmetric.enc.decrypt(key, encrypted, iv = iv)
            Triple(key, payload, signature)
        }
        return ByteArrayInputStream(payload).use {
            val id = it.readUUID()
            if (requested.containsKey(id)) error("Request ID error!")
            //
            val time = it.readLong().milliseconds
            val timeNow = System.currentTimeMillis().milliseconds // todo
//            if (timeNow < time) error("Time error!") // todo IEEE 1588 Precision Time Protocol
            val timeMax = 1.minutes // todo
            if (timeNow - time > timeMax) error("Time is up!")
            for ((k, v) in requested.entries) {
                if (timeNow - v < timeMax) requested.remove(k)
            }
            requested[id] = time
            //
            val body = it.readBytes(it.readInt())
            val issuer = TLSIssuer.of(
                method = method,
                query = query,
                key = key,
                id = id,
            )
            val signee = TLSBytes.toSignee(
                issuer = issuer,
                time = time,
                body = body,
            )
            val verified = asymmetric.signing.verify(keyPair.public, signee, signature = signature)
            if (!verified) error("Not verified!")
            TLSRequest.Decoded(
                issuer = issuer,
                time = time,
                body = body,
            )
        }
    }

    override fun toResponseBody(
        code: Int,
        message: String,
        body: ByteArray?,
        issuer: TLSIssuer,
    ): ByteArray {
        val payload = ByteArrayOutputStream().use {
            it.writeBytes(value = System.currentTimeMillis()) // todo
            if (body == null || body.isEmpty()) {
                it.writeBytes(value = 0)
            } else {
                it.writeBytes(value = body.size)
                it.writeBytes(body)
            }
            it.toByteArray()
        }
        val random: SecureRandom = SecureRandom.getInstanceStrong() // todo
        val iv = ByteArray(TLSBytes.ivSize)
        random.nextBytes(iv)
        val encrypted = symmetric.enc.encrypt(issuer.key, payload, iv = iv)
        val signee = TLSBytes.toSignee(
            issuer = issuer,
            code = code,
            message = message,
            payload = payload,
        )
        val signature = asymmetric.signing.sign(keyPair.private, signee)
        return ByteArrayOutputStream().use {
            it.writeBytes(value = encrypted.size)
            it.writeBytes(encrypted)
            it.writeBytes(iv)
            it.writeBytes(value = signature.size)
            it.writeBytes(signature)
            it.toByteArray()
        }
    }
}
