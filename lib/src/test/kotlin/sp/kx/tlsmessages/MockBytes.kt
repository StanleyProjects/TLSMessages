package sp.kx.tlsmessages

internal fun mockBytes(size: Int = 0): ByteArray {
    return ByteArray(size) { (size - it).toByte() }
}
