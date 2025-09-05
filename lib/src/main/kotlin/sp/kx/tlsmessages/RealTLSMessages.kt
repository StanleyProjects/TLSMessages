package sp.kx.tlsmessages

import sp.kx.bytes.writeBytes
import sp.kx.secrets.Asymmetric
import sp.kx.secrets.Symmetric
import java.io.ByteArrayOutputStream
import java.security.KeyPair
import java.security.SecureRandom
import java.util.UUID

class RealTLSMessages : TLSMessages {
    private val symmetric: Symmetric = Symmetric.AES
    private val asymmetric: Asymmetric = Asymmetric.RSA

    override fun request(keyPair: KeyPair, method: String, query: String, bytes: ByteArray): TLSRequest {
        val method = TLSRequest.getMethodCode(method = method)
        val query = query.toByteArray()
        val key = symmetric.factory.newSecretKey()
        val id = UUID.randomUUID() // todo
        val time = System.currentTimeMillis() // todo
        val payload = ByteArrayOutputStream().use {
            it.writeBytes(value = id)
            it.writeBytes(value = time)
            it.writeBytes(value = bytes.size)
            it.writeBytes(bytes)
            it.toByteArray()
        }
        val encryptedSK = asymmetric.enc.encrypt(keyPair.public, key.encoded)
        val random: SecureRandom = SecureRandom.getInstanceStrong() // todo
        val iv = ByteArray(16)
        random.nextBytes(iv)
        val encrypted = symmetric.enc.encrypt(key, payload, iv = iv)
        val signee = ByteArrayOutputStream().use {
            it.writeBytes(value = id)
            it.writeBytes(value = time)
            it.writeBytes(bytes)
            it.write(method.toInt())
            it.writeBytes(query)
            it.writeBytes(key.encoded)
            it.toByteArray()
        }
        val signature = asymmetric.signing.sign(keyPair.private, signee)
        val body = ByteArrayOutputStream().use {
            it.writeBytes(iv)
            it.writeBytes(value = encryptedSK.size)
            it.writeBytes(encryptedSK)
            it.writeBytes(value = encrypted.size)
            it.writeBytes(encrypted)
            it.writeBytes(value = signature.size)
            it.writeBytes(signature)
            it.toByteArray()
        }
        return TLSRequest(
            method = method,
            query = query,
            key = key,
            id = id,
            body = body,
        )
    }
}
