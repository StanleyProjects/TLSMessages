package sp.kx.tlsmessages

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import sp.kx.secrets.Asymmetric
import sp.kx.secrets.Symmetric
import java.security.KeyPairGenerator

internal class RealTLSTransmitterTest {
    @Test
    fun toRequestTest() {
        val keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair()
        val transmitter = RealTLSTransmitter(
            keyPair = keyPair,
            symmetric = Symmetric.AES,
            asymmetric = Asymmetric.RSA,
        )
        val query = "foo/query"
        val request = transmitter.toRequest(
            method = "POST",
            query = query,
            body = mockBytes(48),
        )
        assertEquals(1, request.issuer.method)
        assertTrue(query.toByteArray().contentEquals(request.issuer.query))
    }
}
