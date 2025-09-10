package sp.kx.tlsmessages

interface TLSMessages {
    fun transmitter(): TLSTransmitter
    fun receiver(): TLSReceiver
}
