package com.appstractive.dnssd.mdns

/**
 * Base class for DNS resource records.
 * Based on RFC 1035 (Domain Names) and RFC 6762 (Multicast DNS).
 */
internal sealed class DNSRecord {
    abstract val name: String
    abstract val ttl: Int
    abstract val type: DNSRecordType
    abstract val clazz: DNSClass

    /**
     * PTR Record - Points to a service instance name.
     * Used for service discovery in DNS-SD.
     */
    data class PTR(
        override val name: String,
        val target: String,
        override val ttl: Int = DNSConstants.MDNS_TTL_DEFAULT,
        override val clazz: DNSClass = DNSClass.IN
    ) : DNSRecord() {
        override val type = DNSRecordType.PTR
    }

    /**
     * SRV Record - Specifies the location of a service.
     * Contains priority, weight, port, and target hostname.
     */
    data class SRV(
        override val name: String,
        val priority: Int,
        val weight: Int,
        val port: Int,
        val target: String,
        override val ttl: Int = DNSConstants.MDNS_TTL_HOST,
        override val clazz: DNSClass = DNSClass.IN_FLUSH_CACHE
    ) : DNSRecord() {
        override val type = DNSRecordType.SRV
    }

    /**
     * A Record - Maps a hostname to an IPv4 address.
     */
    data class A(
        override val name: String,
        val address: String,
        override val ttl: Int = DNSConstants.MDNS_TTL_HOST,
        override val clazz: DNSClass = DNSClass.IN_FLUSH_CACHE
    ) : DNSRecord() {
        override val type = DNSRecordType.A
    }

    /**
     * AAAA Record - Maps a hostname to an IPv6 address.
     */
    data class AAAA(
        override val name: String,
        val address: String,
        override val ttl: Int = DNSConstants.MDNS_TTL_HOST,
        override val clazz: DNSClass = DNSClass.IN_FLUSH_CACHE
    ) : DNSRecord() {
        override val type = DNSRecordType.AAAA
    }

    /**
     * TXT Record - Contains text information.
     * Used in DNS-SD to store service metadata.
     */
    data class TXT(
        override val name: String,
        val attributes: Map<String, ByteArray?>,
        override val ttl: Int = DNSConstants.MDNS_TTL_DEFAULT,
        override val clazz: DNSClass = DNSClass.IN_FLUSH_CACHE
    ) : DNSRecord() {
        override val type = DNSRecordType.TXT

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as TXT

            if (name != other.name) return false
            if (ttl != other.ttl) return false
            if (clazz != other.clazz) return false
            if (attributes.size != other.attributes.size) return false

            for ((key, value) in attributes) {
                val otherValue = other.attributes[key]
                if (value != null && otherValue != null) {
                    if (!value.contentEquals(otherValue)) return false
                } else if ((value == null) != (otherValue == null)) {
                    return false
                }
            }

            return true
        }

        override fun hashCode(): Int {
            var result = name.hashCode()
            result = 31 * result + ttl
            result = 31 * result + clazz.hashCode()
            result = 31 * result + attributes.keys.hashCode()
            return result
        }
    }
}

/**
 * DNS Question - represents a query in a DNS packet.
 */
internal data class DNSQuestion(
    val name: String,
    val type: DNSRecordType,
    val clazz: DNSClass = DNSClass.IN
)

/**
 * Encodes DNS record data to binary format.
 */
internal fun DNSRecord.encodeRecordData(): ByteArray {
    return when (this) {
        is DNSRecord.PTR -> encodePointerData(target)
        is DNSRecord.SRV -> encodeSrvData(priority, weight, port, target)
        is DNSRecord.A -> encodeIpv4Address(address)
        is DNSRecord.AAAA -> encodeIpv6Address(address)
        is DNSRecord.TXT -> encodeTxtData(attributes)
    }
}

/**
 * Encodes a domain name pointer (for PTR records).
 */
private fun encodePointerData(target: String): ByteArray {
    return encodeDomainName(target)
}

/**
 * Encodes SRV record data: priority (2 bytes), weight (2 bytes), port (2 bytes), target (domain name).
 */
private fun encodeSrvData(priority: Int, weight: Int, port: Int, target: String): ByteArray {
    val buffer = mutableListOf<Byte>()

    // Priority (2 bytes, big-endian)
    buffer.add((priority shr 8).toByte())
    buffer.add(priority.toByte())

    // Weight (2 bytes, big-endian)
    buffer.add((weight shr 8).toByte())
    buffer.add(weight.toByte())

    // Port (2 bytes, big-endian)
    buffer.add((port shr 8).toByte())
    buffer.add(port.toByte())

    // Target (domain name)
    buffer.addAll(encodeDomainName(target).toList())

    return buffer.toByteArray()
}

/**
 * Encodes an IPv4 address to 4 bytes.
 */
private fun encodeIpv4Address(address: String): ByteArray {
    val parts = address.split(".")
    require(parts.size == 4) { "Invalid IPv4 address: $address" }

    return ByteArray(4) { i ->
        parts[i].toInt().toByte()
    }
}

/**
 * Encodes an IPv6 address to 16 bytes.
 */
private fun encodeIpv6Address(address: String): ByteArray {
    // Handle IPv6 compression (::)
    val parts = if ("::" in address) {
        val sides = address.split("::")
        val left = if (sides[0].isEmpty()) emptyList() else sides[0].split(":")
        val right = if (sides.size > 1 && sides[1].isNotEmpty()) sides[1].split(":") else emptyList()
        val zeros = List(8 - left.size - right.size) { "0" }
        left + zeros + right
    } else {
        address.split(":")
    }

    require(parts.size == 8) { "Invalid IPv6 address: $address" }

    val bytes = ByteArray(16)
    for (i in parts.indices) {
        val value = parts[i].toInt(16)
        bytes[i * 2] = (value shr 8).toByte()
        bytes[i * 2 + 1] = value.toByte()
    }

    return bytes
}

/**
 * Encodes TXT record attributes as length-prefixed key=value pairs.
 */
private fun encodeTxtData(attributes: Map<String, ByteArray?>): ByteArray {
    if (attributes.isEmpty()) {
        return byteArrayOf(0) // Empty TXT record
    }

    val buffer = mutableListOf<Byte>()

    for ((key, value) in attributes) {
        val pair = if (value != null) {
            "$key=".encodeToByteArray() + value
        } else {
            "$key=".encodeToByteArray()
        }

        // Length prefix (max 255 bytes per attribute)
        require(pair.size <= 255) { "TXT attribute too long: ${pair.size} bytes" }
        buffer.add(pair.size.toByte())
        buffer.addAll(pair.toList())
    }

    return buffer.toByteArray()
}

/**
 * Encodes a domain name in DNS format (length-prefixed labels).
 * Example: "example.local." -> [7]example[5]local[0]
 */
internal fun encodeDomainName(name: String): ByteArray {
    if (name.isEmpty() || name == ".") {
        return byteArrayOf(0)
    }

    val buffer = mutableListOf<Byte>()
    val labels = name.trimEnd('.').split('.')

    for (label in labels) {
        require(label.length <= 63) { "DNS label too long: ${label.length} > 63" }
        buffer.add(label.length.toByte())
        buffer.addAll(label.encodeToByteArray().toList())
    }

    buffer.add(0) // Null terminator

    return buffer.toByteArray()
}

/**
 * Decodes a domain name from DNS format, starting at the given offset.
 * Handles DNS name compression (pointers).
 * Returns the decoded name and the new offset after the name.
 */
internal fun decodeDomainName(data: ByteArray, offset: Int): Pair<String, Int> {
    val labels = mutableListOf<String>()
    var currentOffset = offset
    var jumped = false
    var jumpOffset = offset

    while (currentOffset < data.size) {
        val length = data[currentOffset].toInt() and 0xFF

        if (length == 0) {
            // End of name
            if (!jumped) {
                jumpOffset = currentOffset + 1
            }
            break
        }

        // Check for compression pointer (top 2 bits set)
        if ((length and 0xC0) == 0xC0) {
            // Pointer: read 2 bytes to get offset
            if (currentOffset + 1 >= data.size) break

            val pointerOffset = ((length and 0x3F) shl 8) or (data[currentOffset + 1].toInt() and 0xFF)

            if (!jumped) {
                jumpOffset = currentOffset + 2
                jumped = true
            }

            currentOffset = pointerOffset
            continue
        }

        // Regular label
        if (currentOffset + 1 + length > data.size) break

        val label = data.copyOfRange(currentOffset + 1, currentOffset + 1 + length).decodeToString()
        labels.add(label)

        currentOffset += 1 + length
    }

    val name = if (labels.isEmpty()) "." else labels.joinToString(".") + "."

    return Pair(name, if (jumped) jumpOffset else currentOffset + 1)
}

/**
 * Decodes IPv4 address from 4 bytes.
 */
internal fun decodeIpv4Address(data: ByteArray): String {
    require(data.size == 4) { "IPv4 address must be 4 bytes" }
    return data.joinToString(".") { (it.toInt() and 0xFF).toString() }
}

/**
 * Decodes IPv6 address from 16 bytes.
 */
internal fun decodeIpv6Address(data: ByteArray): String {
    require(data.size == 16) { "IPv6 address must be 16 bytes" }

    val parts = mutableListOf<String>()
    for (i in 0 until 8) {
        val value = ((data[i * 2].toInt() and 0xFF) shl 8) or (data[i * 2 + 1].toInt() and 0xFF)
        parts.add(value.toString(16))
    }

    // Simple compression: replace longest run of zeros with ::
    return parts.joinToString(":")
}

/**
 * Decodes TXT record data (length-prefixed key=value pairs).
 */
internal fun decodeTxtData(data: ByteArray): Map<String, ByteArray?> {
    if (data.isEmpty() || (data.size == 1 && data[0] == 0.toByte())) {
        return emptyMap()
    }

    val attributes = mutableMapOf<String, ByteArray?>()
    var offset = 0

    while (offset < data.size) {
        val length = data[offset].toInt() and 0xFF
        if (length == 0) break

        offset++
        if (offset + length > data.size) break

        val pairBytes = data.copyOfRange(offset, offset + length)
        val pairString = pairBytes.decodeToString()

        val separatorIndex = pairString.indexOf('=')
        if (separatorIndex >= 0) {
            val key = pairString.substring(0, separatorIndex)
            val value = if (separatorIndex + 1 < pairString.length) {
                pairBytes.copyOfRange(separatorIndex + 1, pairBytes.size)
            } else {
                null
            }
            attributes[key] = value
        } else {
            // Key without value
            attributes[pairString] = null
        }

        offset += length
    }

    return attributes
}
