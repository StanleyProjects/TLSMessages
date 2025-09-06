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
import javax.crypto.SecretKey
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes

class RealTLSMessages : TLSMessages {
    private val symmetric: Symmetric = Symmetric.AES
    private val asymmetric: Asymmetric = Asymmetric.RSA

    override fun transmitter(keyPair: KeyPair): TLSTransmitter {
        return RealTLSTransmitter(
            keyPair = keyPair,
            symmetric = symmetric,
            asymmetric = asymmetric,
        )
    }

    override fun fromRequest(
        keyPair: KeyPair,
        method: String,
        query: String,
        bytes: ByteArray,
    ): TLSRequest.Decoded {
        val (key, payload) = ByteArrayInputStream(bytes).use {
            val encryptedKey = it.readBytes(it.readInt())
            val encodedKey = asymmetric.enc.decrypt(keyPair.private, encryptedKey)
            val key = symmetric.factory.toSecretKey(encodedKey)
            val encrypted = it.readBytes(it.readInt())
            val iv = it.readBytes(16)
            key to symmetric.enc.decrypt(key, encrypted, iv = iv)
        }
        return ByteArrayInputStream(payload).use {
            val id = it.readUUID()
            val time = it.readLong().milliseconds
            val body = it.readBytes(it.readInt())
            val issuer = toIssuer(
                method = method,
                query = query,
                key = key,
                id = id,
            )
            val signee = toSignee(
                issuer = issuer,
                time = time,
                body = body,
            )
            val signature = it.readBytes(it.readInt())
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
        keyPair: KeyPair,
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
        val iv = ByteArray(16)
        random.nextBytes(iv)
        val encrypted = symmetric.enc.encrypt(issuer.key, payload, iv = iv)
        val signee = toSignee(
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

    companion object {
        private fun toSignee(
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

        private fun toSignee(
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
}
