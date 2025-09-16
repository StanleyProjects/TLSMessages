package sp.kx.tlsmessages

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import sp.kx.secrets.Asymmetric
import sp.kx.secrets.Symmetric
import java.security.KeyPairGenerator
import java.util.UUID
import kotlin.time.Duration

internal class RealTLSReceiverTest {
    @Test
    fun fromRequestTest() {
        val keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair()
        val transmitter = RealTLSTransmitter(
            keyPair = keyPair,
            symmetric = Symmetric.AES,
            asymmetric = Asymmetric.RSA,
        )
        val method = "POST"
        val query = "foo/query"
        val body = "foo/body".toByteArray()
        val encoded = transmitter.toRequest(
            method = method,
            query = query,
            body = body,
        )
        val requested = mutableMapOf<UUID, Duration>()
        val receiver = RealTLSReceiver(
            keyPair = keyPair,
            symmetric = Symmetric.AES,
            asymmetric = Asymmetric.RSA,
            requested = requested,
        )
        check(requested.isEmpty())
        val decoded = receiver.fromRequest(
            method = method,
            query = query,
            bytes = encoded.bytes,
        )
        assertEquals(encoded.issuer, decoded.issuer)
        assertTrue(body.contentEquals(decoded.body))
        val actual = requested.entries.single()
        assertEquals(encoded.issuer.id, actual.key)
        assertEquals(decoded.time, actual.value)
    }

    @Test
    fun toResponseBodyTest() {
        val keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair()
        val transmitter = RealTLSTransmitter(
            keyPair = keyPair,
            symmetric = Symmetric.AES,
            asymmetric = Asymmetric.RSA,
        )
        val method = "POST"
        val query = "foo/query"
        val requestBody = "foo/body/request".toByteArray()
        val encoded = transmitter.toRequest(
            method = method,
            query = query,
            body = requestBody,
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
        val responseBody = "${String(decoded.body)}/response".toByteArray()
        val bytes = receiver.toResponseBody(
            code = code,
            message = message,
            body = responseBody,
            issuer = encoded.issuer,
        )
        assertTrue(bytes.isNotEmpty())
    }

    @Test
    fun toEmptyResponseBodyTest() {
        val keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair()
        val transmitter = RealTLSTransmitter(
            keyPair = keyPair,
            symmetric = Symmetric.AES,
            asymmetric = Asymmetric.RSA,
        )
        val method = "POST"
        val query = "foo/query"
        val requestBody = "foo/body/request".toByteArray()
        val encoded = transmitter.toRequest(
            method = method,
            query = query,
            body = requestBody,
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
        val bytes = receiver.toResponseBody(
            code = code,
            message = message,
            body = null,
            issuer = encoded.issuer,
        )
        val actual = transmitter.fromResponseBody(
            code = code,
            message = message,
            issuer = encoded.issuer,
            bytes = bytes,
        )
        assertTrue(actual.isEmpty())
    }
}
