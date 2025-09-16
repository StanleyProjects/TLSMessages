package sp.kx.tlsmessages

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

internal class RealTLSMessagesTest {
    @Test
    fun transmitterTest() {
        val messages: TLSMessages = MockRealTLSMessages()
        val transmitter = messages.transmitter()
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
    fun receiverTest() {
        val messages: TLSMessages = MockRealTLSMessages()
        val transmitter = messages.transmitter()
        val method = "POST"
        val query = "foo/query"
        val body = "foo/body".toByteArray()
        val encoded = transmitter.toRequest(
            method = method,
            query = query,
            body = body,
        )
        val receiver = messages.receiver()
        val decoded = receiver.fromRequest(
            method = method,
            query = query,
            bytes = encoded.bytes,
        )
        assertEquals(encoded.issuer, decoded.issuer)
        assertTrue(body.contentEquals(decoded.body))
    }
}
