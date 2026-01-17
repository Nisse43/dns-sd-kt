import com.appstractive.dnssd.DiscoveredService
import com.appstractive.dnssd.DiscoveryEvent
import com.appstractive.dnssd.NetServiceRegisterException
import com.appstractive.dnssd.createNetService
import com.appstractive.dnssd.discoverServices
import com.appstractive.dnssd.key
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

private const val SERVICE_TYPE = "_dnssd-sample._tcp"
private const val SERVICE_NAME = "Linux Sample Service"
private const val SERVICE_PORT = 8080

fun main() = runBlocking {
    // Quick test mode
    if (true) {
        testMain()
        return@runBlocking
    }

    @Suppress("UNREACHABLE_CODE")
    println("DNS-SD Linux Native Sample")
    println("==========================")
    println()

    var running = true
    var publishJob: Job? = null
    var discoverJob: Job? = null

    printHelp()

    while (running) {
        print("\n> ")
        val input = readlnOrNull()?.trim() ?: continue

        when {
            input == "help" || input == "h" -> printHelp()

            input == "publish" || input == "p" -> {
                if (publishJob?.isActive == true) {
                    println("Service is already published. Use 'unpublish' first.")
                } else {
                    publishJob = launch {
                        publishService()
                    }
                    delay(1500) // Allow time for registration (3 announcements with 250ms delays)
                }
            }

            input == "unpublish" || input == "u" -> {
                if (publishJob?.isActive == true) {
                    publishJob.cancel()
                    publishJob = null
                    println("Service unpublished.")
                } else {
                    println("No service is currently published.")
                }
            }

            input == "discover" || input == "d" -> {
                if (discoverJob?.isActive == true) {
                    println("Discovery is already running. Use 'stop' first.")
                } else {
                    discoverJob = launch {
                        discover()
                    }
                    delay(100) // Let the coroutine print initial output
                }
            }

            input == "stop" || input == "s" -> {
                if (discoverJob?.isActive == true) {
                    discoverJob.cancel()
                    discoverJob = null
                    println("Discovery stopped.")
                } else {
                    println("Discovery is not running.")
                }
            }

            input == "quit" || input == "q" -> {
                running = false
                println("Shutting down...")
                publishJob?.cancel()
                discoverJob?.cancel()
            }

            input.isEmpty() -> { }

            else -> {
                println("Unknown command: $input")
                println("Type 'help' for available commands.")
            }
        }
    }
}

private fun printHelp() {
    println("""
        Available commands:
          publish (p)    - Publish a sample service on the network
          unpublish (u)  - Stop publishing the service
          discover (d)   - Start discovering services
          stop (s)       - Stop discovering services
          help (h)       - Show this help
          quit (q)       - Exit the application
    """.trimIndent())
}

private suspend fun publishService() {
    println("Publishing service: $SERVICE_NAME on port $SERVICE_PORT...")

    val service = createNetService(
        type = SERVICE_TYPE,
        name = SERVICE_NAME,
        port = SERVICE_PORT,
        txt = mapOf(
            "version" to "1.0",
            "platform" to "linux-native",
        )
    )

    try {
        service.register()
        println("Service registered successfully!")
        println("  Name: ${service.name}")
        println("  Type: ${service.type}")
        println("  Port: ${service.port}")
        println("  Domain: ${service.domain}")

        service.isRegistered.collect { registered ->
            if (!registered) {
                println("Service registration state changed: unregistered")
            }
        }
    } catch (e: NetServiceRegisterException) {
        println("Failed to register service: ${e.message}")
    } catch (e: CancellationException) {
        service.unregister()
        throw e
    } catch (e: Exception) {
        println("Error during registration: ${e::class.simpleName}: ${e.message}")
    }
}

private suspend fun discover() {
    println("Discovering services of type: $SERVICE_TYPE")
    println("Press 'stop' to end discovery.\n")

    val discoveredServices = mutableMapOf<String, DiscoveredService>()

    discoverServices(SERVICE_TYPE).collect { event ->
        when (event) {
            is DiscoveryEvent.Discovered -> {
                discoveredServices[event.service.key] = event.service
                println("[DISCOVERED] ${event.service.name}")
                println("  Host: ${event.service.host.ifEmpty { "(resolving...)" }}")
                println("  Type: ${event.service.type}")
                event.resolve()
            }

            is DiscoveryEvent.Resolved -> {
                discoveredServices[event.service.key] = event.service
                println("[RESOLVED] ${event.service.name}")
                println("  Host: ${event.service.host}")
                println("  Port: ${event.service.port}")
                println("  Addresses: ${event.service.addresses.joinToString(", ").ifEmpty { "(none)" }}")
                if (event.service.txt.isNotEmpty()) {
                    println("  TXT records:")
                    event.service.txt.forEach { (key, value) ->
                        val valueStr = value?.decodeToString() ?: "(null)"
                        println("    $key = $valueStr")
                    }
                }
            }

            is DiscoveryEvent.Removed -> {
                discoveredServices.remove(event.service.key)
                println("[REMOVED] ${event.service.name}")
            }
        }
        println()
    }
}
