package sp.kx.tlsmessages

import java.security.KeyPair
import java.security.KeyPairGenerator

internal class MockRealTLSMessages : RealTLSMessages() {
    private val _keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair()

    override fun getKeyPair(): KeyPair {
        return _keyPair
    }
}
