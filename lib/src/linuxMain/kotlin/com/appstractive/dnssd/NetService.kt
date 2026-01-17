package com.appstractive.dnssd

import com.appstractive.dnssd.mdns.*
import io.ktor.network.selector.*
import io.ktor.network.sockets.*
import io.ktor.utils.io.core.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.cinterop.*
import platform.linux.*
import platform.posix.*

/**
 * Linux implementation of NetService using Ktor Network for mDNS service registration.
 */
class LinuxNetService(
    override val name: String,
    override val domain: String,
    override val type: String,
    override val port: Int,
    private val priority: Int,
    private val weight: Int,
    private val addresses: List<String>?,
    private val txt: Map<String, String>
) : NetService {

    override val isRegistered = MutableStateFlow(false)

    private var socket: BoundDatagramSocket? = null
    private var selector: SelectorManager? = null
    private var announcementJob: Job? = null
    private val mutex = Mutex()

    private lateinit var hostname: String
    private lateinit var localAddresses: List<String>

    @OptIn(ExperimentalForeignApi::class)
    override suspend fun register(timeoutInMs: Long) {
        println("[DEBUG] register() called")
        mutex.withLock {
            println("[DEBUG] inside mutex.withLock")
            if (isRegistered.value) return@withLock

            withContext(Dispatchers.Default) {
                println("[DEBUG] inside withContext")
                withTimeout(timeoutInMs) {
                    println("[DEBUG] inside withTimeout")
                    // Get hostname
                    hostname = getHostname()
                    println("[DEBUG] hostname: $hostname")

                    // Determine local addresses
                    localAddresses = addresses ?: getLocalAddresses()
                    println("[DEBUG] localAddresses: $localAddresses")

                    if (localAddresses.isEmpty()) {
                        throw NetServiceRegisterException("No network addresses available")
                    }

                    // Create selector and socket
                    println("[DEBUG] creating SelectorManager...")
                    val sel = SelectorManager(Dispatchers.Default)
                    selector = sel
                    println("[DEBUG] SelectorManager created")

                    println("[DEBUG] binding socket...")
                    val sock = aSocket(sel).udp().bind {
                        reuseAddress = true
                    }
                    socket = sock
                    println("[DEBUG] socket bound: ${sock.localAddress}")

                    // Send initial announcements (3 times as per RFC 6762 Section 8.3)
                    repeat(3) {
                        println("[DEBUG] sending announcement ${it + 1}/3...")
                        sendAnnouncement(sock)
                        println("[DEBUG] announcement sent")
                        if (it < 2) delay(250)
                    }

                    // Start periodic announcement job
                    println("[DEBUG] starting periodic job...")
                    announcementJob = launch(Dispatchers.Default) {
                        while (isActive) {
                            delay(60_000) // Re-announce every 60 seconds
                            sendAnnouncement(sock)
                        }
                    }
                    println("[DEBUG] periodic job started")

                    isRegistered.value = true
                    println("[DEBUG] isRegistered set to true")
                }
            }
        }
        println("[DEBUG] register() completed")
    }

    override suspend fun unregister() {
        mutex.withLock {
            if (!isRegistered.value) return@withLock

            withContext(Dispatchers.Default) {
                // Cancel periodic announcements
                announcementJob?.cancel()
                announcementJob = null

                // Send goodbye packets (TTL=0)
                socket?.let { sock ->
                    sendGoodbye(sock)
                }

                // Close socket and selector
                socket?.close()
                socket = null

                selector?.close()
                selector = null

                isRegistered.value = false
            }
        }
    }

    /**
     * Sends mDNS announcement packets.
     */
    private suspend fun sendAnnouncement(socket: BoundDatagramSocket) {
        try {
            val fullServiceName = "$name.$type"
            val fullHostname = "$hostname.local."

            val packet = DNSPacket().apply {
                transactionId = 0
                flags = DNSFlags.STANDARD_RESPONSE

                // PTR record: _service._tcp.local. -> MyService._service._tcp.local.
                answers.add(
                    DNSRecord.PTR(
                        name = type,
                        target = fullServiceName,
                        ttl = DNSConstants.MDNS_TTL_DEFAULT
                    )
                )

                // SRV record: MyService._service._tcp.local. -> hostname.local.:port
                answers.add(
                    DNSRecord.SRV(
                        name = fullServiceName,
                        priority = priority,
                        weight = weight,
                        port = port,
                        target = fullHostname,
                        ttl = DNSConstants.MDNS_TTL_HOST
                    )
                )

                // TXT record: MyService._service._tcp.local. -> attributes
                if (txt.isNotEmpty()) {
                    answers.add(
                        DNSRecord.TXT(
                            name = fullServiceName,
                            attributes = txt.mapValues { it.value.encodeToByteArray() },
                            ttl = DNSConstants.MDNS_TTL_DEFAULT
                        )
                    )
                }

                // A/AAAA records for hostname
                localAddresses.forEach { addr ->
                    if (addr.contains(':')) {
                        // IPv6
                        additionals.add(
                            DNSRecord.AAAA(
                                name = fullHostname,
                                address = addr,
                                ttl = DNSConstants.MDNS_TTL_HOST
                            )
                        )
                    } else {
                        // IPv4
                        additionals.add(
                            DNSRecord.A(
                                name = fullHostname,
                                address = addr,
                                ttl = DNSConstants.MDNS_TTL_HOST
                            )
                        )
                    }
                }
            }

            val data = packet.encode()
            val bytePacket = ByteReadPacket(data)

            socket.send(
                Datagram(
                    packet = bytePacket,
                    address = InetSocketAddress(
                        DNSConstants.MDNS_MULTICAST_IPV4,
                        DNSConstants.MDNS_PORT
                    )
                )
            )
        } catch (e: Exception) {
            // Announcement send failed
        }
    }

    /**
     * Sends goodbye packets (TTL=0) to signal service removal.
     */
    private suspend fun sendGoodbye(socket: BoundDatagramSocket) {
        try {
            val fullServiceName = "$name.$type"

            val packet = DNSPacket().apply {
                transactionId = 0
                flags = DNSFlags.STANDARD_RESPONSE

                // Send PTR with TTL=0 (goodbye)
                answers.add(
                    DNSRecord.PTR(
                        name = type,
                        target = fullServiceName,
                        ttl = DNSConstants.MDNS_TTL_GOODBYE
                    )
                )
            }

            val data = packet.encode()
            val bytePacket = ByteReadPacket(data)

            socket.send(
                Datagram(
                    packet = bytePacket,
                    address = InetSocketAddress(
                        DNSConstants.MDNS_MULTICAST_IPV4,
                        DNSConstants.MDNS_PORT
                    )
                )
            )
        } catch (e: Exception) {
            // Goodbye send failed
        }
    }

    /**
     * Gets the local hostname using POSIX gethostname().
     */
    @OptIn(ExperimentalForeignApi::class)
    private fun getHostname(): String {
        return memScoped {
            val buffer = allocArray<ByteVar>(256)
            val result = gethostname(buffer, 256u)

            if (result == 0) {
                buffer.toKString().takeIf { it.isNotBlank() } ?: "localhost"
            } else {
                "localhost"
            }
        }
    }

    /**
     * Gets local network addresses using POSIX getifaddrs().
     * Returns list of IPv4 and IPv6 addresses excluding loopback and link-local.
     */
    @OptIn(ExperimentalForeignApi::class)
    private fun getLocalAddresses(): List<String> {
        val addresses = mutableListOf<String>()

        memScoped {
            val ifaddrsPtr = alloc<CPointerVar<ifaddrs>>()

            if (getifaddrs(ifaddrsPtr.ptr) == 0) {
                var current = ifaddrsPtr.value

                while (current != null) {
                    val ifa = current.pointed

                    // Check if interface is up and not loopback
                    val flags = ifa.ifa_flags.toInt()
                    val isUp = (flags and IFF_UP) != 0
                    val isLoopback = (flags and IFF_LOOPBACK) != 0

                    if (isUp && !isLoopback && ifa.ifa_addr != null) {
                        val addr = ifa.ifa_addr!!.pointed

                        when (addr.sa_family.toInt()) {
                            AF_INET -> {
                                // IPv4
                                val sin = ifa.ifa_addr!!.reinterpret<sockaddr_in>().pointed
                                val ipBuffer = allocArray<ByteVar>(INET_ADDRSTRLEN)

                                inet_ntop(
                                    AF_INET,
                                    sin.sin_addr.ptr,
                                    ipBuffer,
                                    INET_ADDRSTRLEN.toUInt()
                                )

                                val ipStr = ipBuffer.toKString()
                                if (ipStr.isNotBlank() && !ipStr.startsWith("127.") && !ipStr.startsWith("169.254.")) {
                                    addresses.add(ipStr)
                                }
                            }

                            AF_INET6 -> {
                                // IPv6
                                val sin6 = ifa.ifa_addr!!.reinterpret<sockaddr_in6>().pointed
                                val ipBuffer = allocArray<ByteVar>(INET6_ADDRSTRLEN)

                                inet_ntop(
                                    AF_INET6,
                                    sin6.sin6_addr.ptr,
                                    ipBuffer,
                                    INET6_ADDRSTRLEN.toUInt()
                                )

                                val ipStr = ipBuffer.toKString()
                                // Skip link-local (fe80::) and loopback (::1)
                                if (ipStr.isNotBlank() && !ipStr.startsWith("fe80:") && ipStr != "::1") {
                                    addresses.add(ipStr)
                                }
                            }
                        }
                    }

                    current = ifa.ifa_next
                }

                freeifaddrs(ifaddrsPtr.value)
            }
        }

        return addresses
    }
}

/**
 * Creates a NetService instance for Linux.
 */
actual fun createNetService(
    type: String,
    name: String,
    port: Int,
    priority: Int,
    weight: Int,
    addresses: List<String>?,
    txt: Map<String, String>
): NetService {
    return LinuxNetService(
        name = name,
        domain = "local.",
        type = type.localQualified,
        port = port,
        priority = priority,
        weight = weight,
        addresses = addresses,
        txt = txt
    )
}