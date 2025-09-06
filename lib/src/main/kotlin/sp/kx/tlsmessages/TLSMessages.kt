package sp.kx.tlsmessages

import java.security.KeyPair

interface TLSMessages {
    fun transmitter(keyPair: KeyPair): TLSTransmitter
    fun receiver(keyPair: KeyPair): TLSReceiver
}
