package sp.kx.tlsmessages

import java.security.PublicKey

internal class MockPublicKey(private val encoded: ByteArray? = null) : PublicKey {
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
