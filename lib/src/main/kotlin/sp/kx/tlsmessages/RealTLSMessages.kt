package sp.kx.tlsmessages

import sp.kx.secrets.Asymmetric
import sp.kx.secrets.Symmetric
import java.security.KeyPair
import java.util.UUID
import kotlin.time.Duration

abstract class RealTLSMessages : TLSMessages {
    private val symmetric: Symmetric = Symmetric.AES
    private val asymmetric: Asymmetric = Asymmetric.RSA
    private val requested = mutableMapOf<UUID, Duration>()

    abstract fun getKeyPair(): KeyPair

    override fun transmitter(): TLSTransmitter {
        return RealTLSTransmitter(
            keyPair = getKeyPair(),
            symmetric = symmetric,
            asymmetric = asymmetric,
        )
    }

    override fun receiver(): TLSReceiver {
        return RealTLSReceiver(
            keyPair = getKeyPair(),
            symmetric = symmetric,
            asymmetric = asymmetric,
            requested = requested,
        )
    }
}
