package com.appstractive.dnssd.mdns

/**
 * Constants for mDNS (Multicast DNS) protocol.
 * Based on RFC 6762 (Multicast DNS) and RFC 6763 (DNS-Based Service Discovery).
 */
internal object DNSConstants {
    /** Standard mDNS port */
    const val MDNS_PORT = 5353

    /** IPv4 multicast address for mDNS */
    const val MDNS_MULTICAST_IPV4 = "224.0.0.251"

    /** IPv6 multicast address for mDNS */
    const val MDNS_MULTICAST_IPV6 = "ff02::fb"

    /** Default TTL for service records (PTR, TXT) - 75 minutes */
    const val MDNS_TTL_DEFAULT = 4500

    /** TTL for host records (SRV, A, AAAA) - 2 minutes */
    const val MDNS_TTL_HOST = 120

    /** TTL value indicating a goodbye packet (service removal) */
    const val MDNS_TTL_GOODBYE = 0

    /** Maximum DNS packet size */
    const val MAX_PACKET_SIZE = 9000
}

/**
 * DNS record types used in mDNS/DNS-SD.
 */
internal enum class DNSRecordType(val value: Int) {
    /** IPv4 address record */
    A(1),

    /** Pointer record (service discovery) */
    PTR(12),

    /** Text record (service metadata) */
    TXT(16),

    /** IPv6 address record */
    AAAA(28),

    /** Service record (service location) */
    SRV(33);

    companion object {
        fun fromValue(value: Int): DNSRecordType? = entries.firstOrNull { it.value == value }
    }
}

/**
 * DNS record class values.
 */
internal enum class DNSClass(val value: Int) {
    /** Internet class */
    IN(1),

    /** Internet class with cache-flush bit set (used in mDNS) */
    IN_FLUSH_CACHE(0x8001);

    companion object {
        fun fromValue(value: Int): DNSClass? {
            return when (value) {
                1 -> IN
                0x8001 -> IN_FLUSH_CACHE
                else -> null
            }
        }
    }
}
