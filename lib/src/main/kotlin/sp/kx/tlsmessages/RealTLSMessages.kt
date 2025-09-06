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

class RealTLSMessages : TLSMessages {
    private val symmetric: Symmetric = Symmetric.AES
    private val asymmetric: Asymmetric = Asymmetric.RSA

    override fun toRequest(
        keyPair: KeyPair,
        method: String,
        query: String,
        body: ByteArray,
    ): TLSRequest.Encoded {
        val issuer = toIssuer(
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
        val payload = toBytes(
            id = issuer.id,
            time = time,
            body = body,
        )
        val encrypted = symmetric.enc.encrypt(issuer.key, payload, iv = iv)
        val signee = toSignee(
            id = issuer.id,
            time = time,
            body = body,
            method = issuer.method,
            query = issuer.query,
            key = issuer.key,
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
                id = issuer.id,
                time = time,
                body = body,
                method = issuer.method,
                query = issuer.query,
                key = issuer.key,
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

    private fun toResponseBody(
        code: Int,
        message: String,
        body: ByteArray?,
        issuer: TLSIssuer,
    ): ByteArray {
        val payload = ByteArrayOutputStream().use {
            if (body == null || body.isEmpty()) {
                it.writeBytes(value = 0)
            } else {
                it.writeBytes(value = body.size)
                it.writeBytes(body)
            }
            val time = System.currentTimeMillis().milliseconds // todo
            it.writeBytes(value = time.inWholeMilliseconds)
            it.toByteArray()
        }
        TODO("RealTLSMessages:toResponseBody")
    }

    companion object {
        private fun toIssuer(
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

        private fun toBytes(
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

        private fun toSignee(
            id: UUID,
            time: Duration,
            body: ByteArray,
            method: Int,
            query: ByteArray,
            key: SecretKey,
        ): ByteArray {
            return ByteArrayOutputStream().use {
                it.writeBytes(value = id)
                it.writeBytes(value = time.inWholeMilliseconds)
                it.writeBytes(body)
                it.write(method)
                it.writeBytes(query)
                it.writeBytes(key.encoded)
                it.toByteArray()
            }
        }
    }
}
