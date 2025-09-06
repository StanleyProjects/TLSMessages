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

class RealTLSTransmitter(
    private val keyPair: KeyPair,
    private val symmetric: Symmetric,
    private val asymmetric: Asymmetric,
) : TLSTransmitter {
    override fun toRequest(
        method: String,
        query: String,
        body: ByteArray
    ): TLSRequest.Encoded {
        val issuer = TLSIssuer.of(
            method = method,
            query = query,
            key = symmetric.factory.newSecretKey(),
            id = UUID.randomUUID(), // todo
        )
        val encryptedKey = asymmetric.enc.encrypt(keyPair.public, issuer.key.encoded)
        val random: SecureRandom = SecureRandom.getInstanceStrong() // todo
        val iv = ByteArray(16)
        random.nextBytes(iv)
        val time = System.currentTimeMillis().milliseconds // todo
        val payload = TLSBytes.toPayload(
            id = issuer.id,
            time = time,
            body = body,
        )
        val encrypted = symmetric.enc.encrypt(issuer.key, payload, iv = iv)
        val signee = TLSBytes.toSignee(
            issuer = issuer,
            time = time,
            body = body,
        )
        val signature = asymmetric.signing.sign(keyPair.private, signee)
        val bytes = ByteArrayOutputStream().use {
            it.writeBytes(value = encryptedKey.size)
            it.writeBytes(encryptedKey)
            it.writeBytes(value = encrypted.size)
            it.writeBytes(encrypted)
            it.writeBytes(iv)
            it.writeBytes(value = signature.size)
            it.writeBytes(signature)
            it.toByteArray()
        }
        return TLSRequest.Encoded(
            issuer = issuer,
            bytes = bytes,
        )
    }

    override fun fromResponseBody(
        code: Int,
        message: String,
        issuer: TLSIssuer,
        bytes: ByteArray,
    ): ByteArray {
        val payload = ByteArrayInputStream(bytes).use {
            val encrypted = it.readBytes(it.readInt())
            val iv = it.readBytes(16)
            val payload = symmetric.enc.decrypt(issuer.key, encrypted, iv = iv)
            val signature = it.readBytes(it.readInt())
            val signee = TLSBytes.toSignee(
                issuer = issuer,
                code = code,
                message = message,
                payload = payload,
            )
            val verified = asymmetric.signing.verify(keyPair.public, signee, signature = signature)
            if (!verified) error("Not verified!")
            payload
        }
        return ByteArrayInputStream(payload).use {
            val time = it.readLong().milliseconds
            val timeNow = System.currentTimeMillis().milliseconds // todo
            val timeMax = 1.minutes // todo
//            if (timeNow < time) error("Time error!") // todo IEEE 1588 Precision Time Protocol
            if (timeNow - time > timeMax) error("Time is up!")
            it.readBytes(it.readInt())
        }
    }
}
