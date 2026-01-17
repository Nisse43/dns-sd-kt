import com.appstractive.dnssd.*
import io.ktor.network.selector.*
import io.ktor.network.sockets.*
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.cinterop.*
import platform.posix.*
import platform.linux.*

@OptIn(ExperimentalForeignApi::class)
fun getHostnameTest(): String {
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

@OptIn(ExperimentalForeignApi::class)
fun getLocalAddressesTest(): List<String> {
    val addresses = mutableListOf<String>()
    memScoped {
        val ifaddrsPtr = alloc<CPointerVar<ifaddrs>>()
        if (getifaddrs(ifaddrsPtr.ptr) == 0) {
            var current = ifaddrsPtr.value
            while (current != null) {
                val ifa = current.pointed
                val flags = ifa.ifa_flags.toInt()
                val isUp = (flags and IFF_UP) != 0
                val isLoopback = (flags and IFF_LOOPBACK) != 0
                if (isUp && !isLoopback && ifa.ifa_addr != null) {
                    val addr = ifa.ifa_addr!!.pointed
                    when (addr.sa_family.toInt()) {
                        AF_INET -> {
                            val sin = ifa.ifa_addr!!.reinterpret<sockaddr_in>().pointed
                            val ipBuffer = allocArray<ByteVar>(INET_ADDRSTRLEN)
                            inet_ntop(AF_INET, sin.sin_addr.ptr, ipBuffer, INET_ADDRSTRLEN.toUInt())
                            val ipStr = ipBuffer.toKString()
                            if (ipStr.isNotBlank() && !ipStr.startsWith("127.") && !ipStr.startsWith("169.254.")) {
                                addresses.add(ipStr)
                            }
                        }
                        AF_INET6 -> {
                            val sin6 = ifa.ifa_addr!!.reinterpret<sockaddr_in6>().pointed
                            val ipBuffer = allocArray<ByteVar>(INET6_ADDRSTRLEN)
                            inet_ntop(AF_INET6, sin6.sin6_addr.ptr, ipBuffer, INET6_ADDRSTRLEN.toUInt())
                            val ipStr = ipBuffer.toKString()
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

fun testMain() = runBlocking {
    println("Testing POSIX functions...")

    // Test hostname
    println("1. Testing gethostname()...")
    val hostname = try {
        getHostnameTest()
    } catch (e: Exception) {
        println("   FAILED: ${e::class.simpleName}: ${e.message}")
        return@runBlocking
    }
    println("   OK: $hostname")

    // Test getifaddrs
    println("2. Testing getifaddrs()...")
    val addresses = try {
        getLocalAddressesTest()
    } catch (e: Exception) {
        println("   FAILED: ${e::class.simpleName}: ${e.message}")
        return@runBlocking
    }
    println("   OK: $addresses")

    if (addresses.isEmpty()) {
        println("   WARNING: No addresses found!")
    }

    println("\nTracing library register() logic...")

    val mutex = Mutex()

    // Step 1: mutex.withLock
    println("1. Testing mutex.withLock...")
    try {
        withTimeout(2000) {
            mutex.withLock {
                println("   Inside lock")
            }
        }
        println("   OK")
    } catch (e: Exception) {
        println("   FAILED: ${e::class.simpleName}: ${e.message}")
        return@runBlocking
    }

    // Step 2: withContext(Dispatchers.Default) inside runBlocking
    println("2. Testing withContext(Dispatchers.Default)...")
    try {
        withTimeout(2000) {
            withContext(Dispatchers.Default) {
                println("   Inside Dispatchers.Default context")
            }
        }
        println("   OK")
    } catch (e: Exception) {
        println("   FAILED: ${e::class.simpleName}: ${e.message}")
        return@runBlocking
    }

    // Step 3: Combined - mutex + withContext
    println("3. Testing mutex.withLock + withContext(Dispatchers.Default)...")
    try {
        withTimeout(2000) {
            mutex.withLock {
                withContext(Dispatchers.Default) {
                    println("   Inside both")
                }
            }
        }
        println("   OK")
    } catch (e: Exception) {
        println("   FAILED: ${e::class.simpleName}: ${e.message}")
        return@runBlocking
    }

    // Step 4: Create selector inside withContext
    println("4. Testing SelectorManager inside withContext...")
    try {
        withTimeout(5000) {
            mutex.withLock {
                withContext(Dispatchers.Default) {
                    val sel = SelectorManager(Dispatchers.Default)
                    println("   Selector created")
                    val sock = aSocket(sel).udp().bind { reuseAddress = true }
                    println("   Socket bound: ${sock.localAddress}")
                    sock.close()
                    sel.close()
                }
            }
        }
        println("   OK")
    } catch (e: Exception) {
        println("   FAILED: ${e::class.simpleName}: ${e.message}")
        return@runBlocking
    }

    // Step 5: Send mDNS packet
    println("5. Testing send inside withContext...")
    try {
        withTimeout(5000) {
            mutex.withLock {
                withContext(Dispatchers.Default) {
                    val sel = SelectorManager(Dispatchers.Default)
                    val sock = aSocket(sel).udp().bind { reuseAddress = true }
                    println("   Sending packet...")
                    val data = "test".encodeToByteArray()
                    sock.send(Datagram(
                        packet = io.ktor.utils.io.core.ByteReadPacket(data),
                        address = InetSocketAddress("224.0.0.251", 5353)
                    ))
                    println("   Packet sent")
                    sock.close()
                    sel.close()
                }
            }
        }
        println("   OK")
    } catch (e: Exception) {
        println("   FAILED: ${e::class.simpleName}: ${e.message}")
        return@runBlocking
    }

    println("\nAll steps passed! Now testing actual library...")

    val service = createNetService(
        type = "_test._tcp",
        name = "TestService",
        port = 8080,
    )

    println("Service created: ${service.name}")
    println("Registering...")

    try {
        withTimeout(15000) {
            service.register(timeoutInMs = 10000)
        }
        println("Registration successful!")
    } catch (e: TimeoutCancellationException) {
        println("Registration timed out")
    } catch (e: Exception) {
        println("Registration failed: ${e::class.simpleName}: ${e.message}")
    }

    println("Test complete")
}
