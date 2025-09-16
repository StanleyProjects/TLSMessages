package sp.kx.tlsmessages

import javax.crypto.SecretKey

internal class MockSecretKey(
    private val encoded: ByteArray? = null,
) : SecretKey {
    override fun getAlgorithm(): String? {
        return null
    }

    override fun getFormat(): String? {
        return null
    }

    override fun getEncoded(): ByteArray? {
        return encoded
    }
}
