package com.appstractive.dnssd

import com.appstractive.dnssd.mdns.*
import io.ktor.network.selector.*
import io.ktor.network.sockets.*
import io.ktor.utils.io.core.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

actual fun discoverServices(type: String): Flow<DiscoveryEvent> = callbackFlow {
    val selector = SelectorManager(Dispatchers.Default)
    var socket: BoundDatagramSocket? = null

    try {
        socket = withContext(Dispatchers.Default) {
            aSocket(selector).udp().bind(InetSocketAddress("0.0.0.0", DNSConstants.MDNS_PORT)) {
                reuseAddress = true
            }
        }

        // Send initial query
        sendQuery(socket, type.localQualified)

        // Track discovered services
        val discoveredServices = mutableMapOf<String, DiscoveredService>()

        // Launch receiver coroutine
        launch(Dispatchers.Default) {
            while (isActive) {
                try {
                    val datagram = socket.receive()
                    val packet = datagram.packet

                    // Read packet data
                    val length = packet.remaining
                    if (length > 0) {
                        @Suppress("DEPRECATION")
                        val data = packet.readBytes()

                        // Decode DNS packet
                        val dnsPacket = DNSPacket.decode(data) ?: continue

                        // Process packet
                        processPacket(
                            packet = dnsPacket,
                            serviceType = type.localQualified,
                            discoveredServices = discoveredServices,
                            sendQuery = { queryType ->
                                launch(Dispatchers.Default) {
                                    sendQuery(socket, queryType)
                                }
                            },
                            emit = { event ->
                                trySend(event)
                            }
                        )
                    }
                } catch (e: Exception) {
                    // Continue listening even on errors
                    if (!isActive) break
                }
            }
        }

    } catch (e: Exception) {
        close(e)
    }

    awaitClose {
        socket?.close()
        selector.close()
    }
}

/**
 * Sends a DNS query for the specified service type.
 */
private suspend fun sendQuery(socket: BoundDatagramSocket, serviceType: String) {
    try {
        val query = DNSPacket().apply {
            transactionId = 0
            flags = DNSFlags.STANDARD_QUERY

            questions.add(
                DNSQuestion(
                    name = serviceType,
                    type = DNSRecordType.PTR,
                    clazz = DNSClass.IN
                )
            )
        }

        val data = query.encode()
        val packet = ByteReadPacket(data)

        socket.send(
            Datagram(
                packet = packet,
                address = InetSocketAddress(
                    DNSConstants.MDNS_MULTICAST_IPV4,
                    DNSConstants.MDNS_PORT
                )
            )
        )
    } catch (e: Exception) {
        // Query send failed
    }
}

/**
 * Processes a received DNS packet and emits discovery events.
 */
private fun processPacket(
    packet: DNSPacket,
    serviceType: String,
    discoveredServices: MutableMap<String, DiscoveredService>,
    sendQuery: (String) -> Unit,
    emit: (DiscoveryEvent) -> Unit
) {
    // Process PTR records for service discovery
    val ptrRecords = packet.answers.filterIsInstance<DNSRecord.PTR>()
        .filter { it.name.equals(serviceType, ignoreCase = true) }

    for (ptr in ptrRecords) {
        val serviceName = extractServiceName(ptr.target, serviceType)

        // TTL 0 means goodbye (service removed)
        if (ptr.ttl == DNSConstants.MDNS_TTL_GOODBYE) {
            val service = DiscoveredService(
                name = serviceName,
                addresses = emptyList(),
                host = "",
                type = serviceType,
                port = 0,
                txt = emptyMap()
            )

            discoveredServices.remove(service.key)

            emit(
                DiscoveryEvent.Removed(service = service)
            )
            continue
        }

        // Find associated SRV, TXT, A, AAAA records
        val srvRecord = findSRVRecord(packet, ptr.target)
        val txtRecord = findTXTRecord(packet, ptr.target)
        val addresses = if (srvRecord != null) {
            findAddresses(packet, srvRecord.target)
        } else {
            emptyList()
        }

        val service = DiscoveredService(
            name = serviceName,
            addresses = addresses,
            host = srvRecord?.target ?: "",
            type = serviceType,
            port = srvRecord?.port ?: 0,
            txt = txtRecord?.attributes?.mapValues { it.value } ?: emptyMap()
        )

        if (addresses.isEmpty() && srvRecord != null) {
            // Emit discovered, need resolution
            discoveredServices[service.key] = service

            emit(
                DiscoveryEvent.Discovered(
                    service = service,
                    resolve = {
                        // Send A/AAAA queries for the hostname
                        sendQuery(srvRecord.target)
                    }
                )
            )
        } else {
            // Already resolved
            discoveredServices[service.key] = service

            emit(
                DiscoveryEvent.Resolved(
                    service = service,
                    resolve = {
                        // Re-query if needed
                        if (srvRecord != null) {
                            sendQuery(srvRecord.target)
                        }
                    }
                )
            )
        }
    }

    // Process A/AAAA records for previously discovered services
    processAddressRecords(packet, discoveredServices, serviceType, emit)
}

/**
 * Processes A and AAAA records to update discovered services with addresses.
 */
private fun processAddressRecords(
    packet: DNSPacket,
    discoveredServices: MutableMap<String, DiscoveredService>,
    serviceType: String,
    emit: (DiscoveryEvent) -> Unit
) {
    val addressRecords = (packet.answers + packet.additionals)
        .filter { it is DNSRecord.A || it is DNSRecord.AAAA }

    for (service in discoveredServices.values.toList()) {
        if (service.host.isEmpty()) continue

        val newAddresses = addressRecords
            .filter { record ->
                record.name.equals(service.host, ignoreCase = true)
            }
            .map { record ->
                when (record) {
                    is DNSRecord.A -> record.address
                    is DNSRecord.AAAA -> record.address
                    else -> null
                }
            }
            .filterNotNull()

        if (newAddresses.isNotEmpty() && newAddresses != service.addresses) {
            val updatedService = service.copy(addresses = service.addresses + newAddresses)
            discoveredServices[service.key] = updatedService

            emit(
                DiscoveryEvent.Resolved(
                    service = updatedService,
                    resolve = {
                        // No-op, already resolved
                    }
                )
            )
        }
    }
}

/**
 * Finds the SRV record for a given service instance name.
 */
private fun findSRVRecord(packet: DNSPacket, name: String): DNSRecord.SRV? {
    return (packet.answers + packet.additionals)
        .filterIsInstance<DNSRecord.SRV>()
        .firstOrNull { it.name.equals(name, ignoreCase = true) }
}

/**
 * Finds the TXT record for a given service instance name.
 */
private fun findTXTRecord(packet: DNSPacket, name: String): DNSRecord.TXT? {
    return (packet.answers + packet.additionals)
        .filterIsInstance<DNSRecord.TXT>()
        .firstOrNull { it.name.equals(name, ignoreCase = true) }
}

/**
 * Finds all addresses (A and AAAA records) for a given hostname.
 */
private fun findAddresses(packet: DNSPacket, hostname: String): List<String> {
    val addresses = mutableListOf<String>()

    (packet.answers + packet.additionals).forEach { record ->
        when (record) {
            is DNSRecord.A -> {
                if (record.name.equals(hostname, ignoreCase = true)) {
                    addresses.add(record.address)
                }
            }

            is DNSRecord.AAAA -> {
                if (record.name.equals(hostname, ignoreCase = true)) {
                    addresses.add(record.address)
                }
            }

            else -> {}
        }
    }

    return addresses
}

/**
 * Extracts the service name from the full service instance name.
 * Example: "My Service._http._tcp.local." with type "_http._tcp.local." returns "My Service"
 */
private fun extractServiceName(fullName: String, serviceType: String): String {
    return fullName
        .removeSuffix(".$serviceType")
        .removeSuffix(".")
        .removeSuffix(serviceType)
}
