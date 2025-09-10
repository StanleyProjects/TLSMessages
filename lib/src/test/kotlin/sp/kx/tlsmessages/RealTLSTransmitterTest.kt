package sp.kx.tlsmessages

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import sp.kx.secrets.Asymmetric
import sp.kx.secrets.Symmetric
import java.security.KeyPairGenerator
import java.util.UUID
import kotlin.time.Duration

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

    @Test
    fun fromResponseBodyTest() {
        val keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair()
        val transmitter = RealTLSTransmitter(
            keyPair = keyPair,
            symmetric = Symmetric.AES,
            asymmetric = Asymmetric.RSA,
        )
        val method = "POST"
        val query = "foo/query"
        val encoded = transmitter.toRequest(
            method = method,
            query = query,
            body = "foo/body/request".toByteArray(),
        )
        val requested = mutableMapOf<UUID, Duration>()
        val receiver = RealTLSReceiver(
            keyPair = keyPair,
            symmetric = Symmetric.AES,
            asymmetric = Asymmetric.RSA,
            requested = requested,
        )
        val decoded = receiver.fromRequest(
            method = method,
            query = query,
            bytes = encoded.bytes,
        )
        val code = 42
        val message = "foo/message"
        val expected = "${String(decoded.body)}/response".toByteArray()
        val bytes = receiver.toResponseBody(
            code = code,
            message = message,
            body = expected,
            issuer = encoded.issuer,
        )
        val actual = transmitter.fromResponseBody(
            code = code,
            message = message,
            issuer = encoded.issuer,
            bytes = bytes,
        )
        assertTrue(expected.contentEquals(actual))
    }
}
