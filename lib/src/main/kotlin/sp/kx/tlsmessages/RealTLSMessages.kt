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
import kotlin.time.Duration.Companion.milliseconds

class RealTLSMessages : TLSMessages {
    private val symmetric: Symmetric = Symmetric.AES
    private val asymmetric: Asymmetric = Asymmetric.RSA
    private val timeMax: Long = 1_000 * 60

    override fun toRequest(
        keyPair: KeyPair,
        method: String,
        query: String,
        bytes: ByteArray,
    ): TLSRequest {
        val payload = TLSPayload(
            id = UUID.randomUUID(), // todo
            time = System.currentTimeMillis().milliseconds, // todo
            bytes = bytes,
        )
        val issuer = toIssuer(
            method = method,
            query = query,
            key = symmetric.factory.newSecretKey(),
            id = payload.id,
        )
        val encryptedKey = asymmetric.enc.encrypt(keyPair.public, issuer.key.encoded)
        val random: SecureRandom = SecureRandom.getInstanceStrong() // todo
        val iv = ByteArray(16)
        random.nextBytes(iv)
        val encrypted = symmetric.enc.encrypt(issuer.key, toBytes(payload = payload), iv = iv)
        val signee = toSignee(payload = payload, issuer = issuer)
        val signature = asymmetric.signing.sign(keyPair.private, signee)
        val body = ByteArrayOutputStream().use {
            it.writeBytes(value = encryptedKey.size)
            it.writeBytes(encryptedKey)
            it.writeBytes(value = encrypted.size)
            it.writeBytes(encrypted)
            it.writeBytes(iv)
            it.writeBytes(value = signature.size)
            it.writeBytes(signature)
            it.toByteArray()
        }
        return TLSRequest(
            issuer = issuer,
            body = body,
        )
    }

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

    private fun toBytes(payload: TLSPayload): ByteArray {
        return ByteArrayOutputStream().use {
            it.writeBytes(value = payload.id)
            it.writeBytes(value = payload.time.inWholeMilliseconds)
            it.writeBytes(value = payload.bytes.size)
            it.writeBytes(payload.bytes)
            it.toByteArray()
        }
    }

    private fun toPayload(encoded: ByteArray): TLSPayload {
        return ByteArrayInputStream(encoded).use {
            TLSPayload(
                id = it.readUUID(),
                time = it.readLong().milliseconds,
                bytes = it.readBytes(it.readInt()),
            )
        }
    }

    private fun toSignee(payload: TLSPayload, issuer: TLSIssuer): ByteArray {
        return ByteArrayOutputStream().use {
            it.writeBytes(value = payload.id)
            it.writeBytes(value = payload.time.inWholeMilliseconds)
            it.writeBytes(payload.bytes)
            it.write(issuer.method.toInt())
            it.writeBytes(issuer.query)
            it.writeBytes(issuer.key.encoded)
            it.toByteArray()
        }
    }

    private fun fromRequest(
        keyPair: KeyPair,
        method: String,
        query: String,
        bytes: ByteArray,
    ): TLSIssuer {
        return ByteArrayInputStream(bytes).use {
            val encryptedKey = it.readBytes(it.readInt())
            val encodedKey = asymmetric.enc.decrypt(keyPair.private, encryptedKey)
            val key = symmetric.factory.toSecretKey(encodedKey)
            val encrypted = it.readBytes(it.readInt())
            val iv = it.readBytes(16)
            val payload = toPayload(encoded = symmetric.enc.decrypt(key, encrypted, iv = iv))
            val issuer = toIssuer(
                method = method,
                query = query,
                key = key,
                id = payload.id,
            )
            val signee = toSignee(payload = payload, issuer = issuer)
            val signature = it.readBytes(it.readInt())
            val verified = asymmetric.signing.verify(keyPair.public, signee, signature = signature)
            if (!verified) error("Not verified!")
            issuer
        }
    }

    override fun fromResponse(issuer: TLSIssuer, body: ByteArray): ByteArray {
        ByteArrayInputStream(body).use {
            val iv = it.readBytes(16)
            val encrypted = it.readBytes(it.readInt())
            val payload = symmetric.enc.decrypt(issuer.key, encrypted, iv = iv)
            ByteArrayInputStream(payload).use { stream ->
                val id = stream.readUUID()
                val time = stream.readLong()
                val timeNow = System.currentTimeMillis() // todo
//              if (timeNow < time) error("Time error!") // todo IEEE 1588 Precision Time Protocol
                if (timeNow - time > timeMax) error("Time is up!") // todo
            }

        }
        TODO("RealTLSMessages:fromResponse")
    }
}
