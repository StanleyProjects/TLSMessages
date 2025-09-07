package sp.kx.tlsmessages

import java.security.PrivateKey

internal class MockPrivateKey(private val encoded: ByteArray? = null) : PrivateKey {
    override fun getAlgorithm(): String? {
        return null
    }

    override fun getFormat(): String? {
        return null
    }

    override fun getEncoded(): ByteArray? {
        TODO("getEncoded")
    }
}
