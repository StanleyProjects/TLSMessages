package sp.kx.tlsmessages

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.Objects
import java.util.UUID
import javax.crypto.SecretKey

internal class TLSIssuerTest {
    @Test
    fun toStringTest() {
        val method = "POST"
        val query = "foo/query"
        val id = UUID(0, 42)
        val issuer = TLSIssuer.of(
            id = id,
            method = method,
            query = query,
            key = MockSecretKey(),
        )
        val expected = "TLSIssuer($id)"
        val actual = issuer.toString()
        assertEquals(expected, actual)
    }

    @Test
    fun hashCodeTest() {
        val method = "POST"
        val query = "foo/query"
        val id = UUID(0, 42)
        val key: SecretKey = MockSecretKey(encoded = mockBytes(42))
        val issuer = TLSIssuer.of(
            id = id,
            method = method,
            query = query,
            key = key,
        )
        val expected = Objects.hash(
            id,
            1,
            query.toByteArray().contentHashCode(),
            key.encoded.contentHashCode(),
        )
        val actual = issuer.hashCode()
        assertEquals(expected, actual)
    }

    @Test
    fun equalsTest() {
        val method = "POST"
        val query = "foo/query"
        val id = UUID(0, 42)
        val key: SecretKey = MockSecretKey(encoded = mockBytes(42))
        val i0 = TLSIssuer.of(
            id = id,
            method = method,
            query = query,
            key = key,
        )
        val i1 = TLSIssuer.of(
            id = id,
            method = method,
            query = query,
            key = key,
        )
        assertTrue(i0 == i1)
        listOf(
            TLSIssuer.of(
                id = UUID(0, 0),
                method = method,
                query = query,
                key = key,
            ),
            TLSIssuer.of(
                id = id,
                method = method,
                query = "foo/bar",
                key = key,
            ),
            TLSIssuer.of(
                id = id,
                method = method,
                query = query,
                key = MockSecretKey(encoded = mockBytes(1)),
            ),
        ).forEach { i2 ->
            assertTrue(i0 != i2)
        }
        assertTrue(!i0.equals(Unit))
    }
}
