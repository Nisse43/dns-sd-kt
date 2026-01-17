package com.appstractive.dnssd.mdns

/**
 * Represents a complete DNS packet with header and resource record sections.
 * Based on RFC 1035 (Domain Names) and RFC 6762 (Multicast DNS).
 */
internal class DNSPacket {
    /** Transaction ID (0 for mDNS responses) */
    var transactionId: Int = 0

    /** Flags field containing QR, Opcode, AA, TC, RD, RA, Z, RCODE */
    var flags: Int = 0

    /** Questions section */
    val questions: MutableList<DNSQuestion> = mutableListOf()

    /** Answers section */
    val answers: MutableList<DNSRecord> = mutableListOf()

    /** Authority records section (rarely used in mDNS) */
    val authorities: MutableList<DNSRecord> = mutableListOf()

    /** Additional records section */
    val additionals: MutableList<DNSRecord> = mutableListOf()

    /**
     * Encodes this DNS packet to binary format.
     * Format: Header (12 bytes) + Questions + Answers + Authority + Additional
     */
    fun encode(): ByteArray {
        val buffer = mutableListOf<Byte>()

        // Header (12 bytes)
        buffer.addAll(encodeHeader())

        // Questions
        for (question in questions) {
            buffer.addAll(encodeQuestion(question).toList())
        }

        // Answers
        for (record in answers) {
            buffer.addAll(encodeRecord(record).toList())
        }

        // Authority (rarely used)
        for (record in authorities) {
            buffer.addAll(encodeRecord(record).toList())
        }

        // Additional
        for (record in additionals) {
            buffer.addAll(encodeRecord(record).toList())
        }

        return buffer.toByteArray()
    }

    /**
     * Encodes the DNS header (12 bytes).
     * Format:
     * - Transaction ID (2 bytes)
     * - Flags (2 bytes)
     * - Question count (2 bytes)
     * - Answer count (2 bytes)
     * - Authority count (2 bytes)
     * - Additional count (2 bytes)
     */
    private fun encodeHeader(): List<Byte> {
        val header = mutableListOf<Byte>()

        // Transaction ID (2 bytes)
        header.add((transactionId shr 8).toByte())
        header.add(transactionId.toByte())

        // Flags (2 bytes)
        header.add((flags shr 8).toByte())
        header.add(flags.toByte())

        // Question count (2 bytes)
        header.add((questions.size shr 8).toByte())
        header.add(questions.size.toByte())

        // Answer count (2 bytes)
        header.add((answers.size shr 8).toByte())
        header.add(answers.size.toByte())

        // Authority count (2 bytes)
        header.add((authorities.size shr 8).toByte())
        header.add(authorities.size.toByte())

        // Additional count (2 bytes)
        header.add((additionals.size shr 8).toByte())
        header.add(additionals.size.toByte())

        return header
    }

    /**
     * Encodes a DNS question.
     * Format: Name + Type (2 bytes) + Class (2 bytes)
     */
    private fun encodeQuestion(question: DNSQuestion): ByteArray {
        val buffer = mutableListOf<Byte>()

        // Name
        buffer.addAll(encodeDomainName(question.name).toList())

        // Type (2 bytes)
        buffer.add((question.type.value shr 8).toByte())
        buffer.add(question.type.value.toByte())

        // Class (2 bytes)
        buffer.add((question.clazz.value shr 8).toByte())
        buffer.add(question.clazz.value.toByte())

        return buffer.toByteArray()
    }

    /**
     * Encodes a DNS resource record.
     * Format: Name + Type (2 bytes) + Class (2 bytes) + TTL (4 bytes) + Data Length (2 bytes) + Data
     */
    private fun encodeRecord(record: DNSRecord): ByteArray {
        val buffer = mutableListOf<Byte>()

        // Name
        buffer.addAll(encodeDomainName(record.name).toList())

        // Type (2 bytes)
        buffer.add((record.type.value shr 8).toByte())
        buffer.add(record.type.value.toByte())

        // Class (2 bytes)
        buffer.add((record.clazz.value shr 8).toByte())
        buffer.add(record.clazz.value.toByte())

        // TTL (4 bytes)
        buffer.add((record.ttl shr 24).toByte())
        buffer.add((record.ttl shr 16).toByte())
        buffer.add((record.ttl shr 8).toByte())
        buffer.add(record.ttl.toByte())

        // Data
        val data = record.encodeRecordData()

        // Data Length (2 bytes)
        buffer.add((data.size shr 8).toByte())
        buffer.add(data.size.toByte())

        // Data
        buffer.addAll(data.toList())

        return buffer.toByteArray()
    }

    companion object {
        /**
         * Decodes a DNS packet from binary format.
         * Returns null if the packet is malformed.
         */
        fun decode(data: ByteArray): DNSPacket? {
            return try {
                val packet = DNSPacket()
                var offset = 0

                // Parse header (12 bytes)
                if (data.size < 12) return null

                packet.transactionId = ((data[0].toInt() and 0xFF) shl 8) or (data[1].toInt() and 0xFF)
                packet.flags = ((data[2].toInt() and 0xFF) shl 8) or (data[3].toInt() and 0xFF)

                val questionCount = ((data[4].toInt() and 0xFF) shl 8) or (data[5].toInt() and 0xFF)
                val answerCount = ((data[6].toInt() and 0xFF) shl 8) or (data[7].toInt() and 0xFF)
                val authorityCount = ((data[8].toInt() and 0xFF) shl 8) or (data[9].toInt() and 0xFF)
                val additionalCount = ((data[10].toInt() and 0xFF) shl 8) or (data[11].toInt() and 0xFF)

                offset = 12

                // Parse questions
                repeat(questionCount) {
                    val (question, newOffset) = decodeQuestion(data, offset) ?: return null
                    packet.questions.add(question)
                    offset = newOffset
                }

                // Parse answers
                repeat(answerCount) {
                    val (record, newOffset) = decodeRecord(data, offset) ?: return null
                    packet.answers.add(record)
                    offset = newOffset
                }

                // Parse authority records
                repeat(authorityCount) {
                    val (record, newOffset) = decodeRecord(data, offset) ?: return null
                    packet.authorities.add(record)
                    offset = newOffset
                }

                // Parse additional records
                repeat(additionalCount) {
                    val (record, newOffset) = decodeRecord(data, offset) ?: return null
                    packet.additionals.add(record)
                    offset = newOffset
                }

                packet
            } catch (e: Exception) {
                // Malformed packet
                null
            }
        }

        /**
         * Decodes a DNS question starting at the given offset.
         * Returns the question and the new offset, or null if malformed.
         */
        private fun decodeQuestion(data: ByteArray, offset: Int): Pair<DNSQuestion, Int>? {
            return try {
                // Decode name
                val (name, nameEndOffset) = decodeDomainName(data, offset)

                // Type (2 bytes)
                if (nameEndOffset + 4 > data.size) return null

                val typeValue = ((data[nameEndOffset].toInt() and 0xFF) shl 8) or
                        (data[nameEndOffset + 1].toInt() and 0xFF)

                // Class (2 bytes)
                val classValue = ((data[nameEndOffset + 2].toInt() and 0xFF) shl 8) or
                        (data[nameEndOffset + 3].toInt() and 0xFF)

                val type = DNSRecordType.fromValue(typeValue) ?: return null
                val clazz = DNSClass.fromValue(classValue) ?: DNSClass.IN

                val question = DNSQuestion(name, type, clazz)

                Pair(question, nameEndOffset + 4)
            } catch (e: Exception) {
                null
            }
        }

        /**
         * Decodes a DNS resource record starting at the given offset.
         * Returns the record and the new offset, or null if malformed.
         */
        private fun decodeRecord(data: ByteArray, offset: Int): Pair<DNSRecord, Int>? {
            return try {
                // Decode name
                val (name, nameEndOffset) = decodeDomainName(data, offset)

                // Type (2 bytes)
                if (nameEndOffset + 10 > data.size) return null

                val typeValue = ((data[nameEndOffset].toInt() and 0xFF) shl 8) or
                        (data[nameEndOffset + 1].toInt() and 0xFF)

                // Class (2 bytes)
                val classValue = ((data[nameEndOffset + 2].toInt() and 0xFF) shl 8) or
                        (data[nameEndOffset + 3].toInt() and 0xFF)

                // TTL (4 bytes)
                val ttl = ((data[nameEndOffset + 4].toInt() and 0xFF) shl 24) or
                        ((data[nameEndOffset + 5].toInt() and 0xFF) shl 16) or
                        ((data[nameEndOffset + 6].toInt() and 0xFF) shl 8) or
                        (data[nameEndOffset + 7].toInt() and 0xFF)

                // Data length (2 bytes)
                val dataLength = ((data[nameEndOffset + 8].toInt() and 0xFF) shl 8) or
                        (data[nameEndOffset + 9].toInt() and 0xFF)

                // Data
                val dataStart = nameEndOffset + 10
                val dataEnd = dataStart + dataLength
                if (dataEnd > data.size) return null

                val recordData = data.copyOfRange(dataStart, dataEnd)

                val type = DNSRecordType.fromValue(typeValue) ?: return null
                val clazz = DNSClass.fromValue(classValue) ?: DNSClass.IN

                // Decode record based on type
                val record = when (type) {
                    DNSRecordType.PTR -> {
                        val (target, _) = decodeDomainName(data, dataStart)
                        DNSRecord.PTR(name, target, ttl, clazz)
                    }

                    DNSRecordType.SRV -> {
                        if (recordData.size < 6) return null
                        val priority = ((recordData[0].toInt() and 0xFF) shl 8) or
                                (recordData[1].toInt() and 0xFF)
                        val weight = ((recordData[2].toInt() and 0xFF) shl 8) or
                                (recordData[3].toInt() and 0xFF)
                        val port = ((recordData[4].toInt() and 0xFF) shl 8) or
                                (recordData[5].toInt() and 0xFF)
                        val (target, _) = decodeDomainName(data, dataStart + 6)
                        DNSRecord.SRV(name, priority, weight, port, target, ttl, clazz)
                    }

                    DNSRecordType.A -> {
                        if (recordData.size != 4) return null
                        val address = decodeIpv4Address(recordData)
                        DNSRecord.A(name, address, ttl, clazz)
                    }

                    DNSRecordType.AAAA -> {
                        if (recordData.size != 16) return null
                        val address = decodeIpv6Address(recordData)
                        DNSRecord.AAAA(name, address, ttl, clazz)
                    }

                    DNSRecordType.TXT -> {
                        val attributes = decodeTxtData(recordData)
                        DNSRecord.TXT(name, attributes, ttl, clazz)
                    }
                }

                Pair(record, dataEnd)
            } catch (e: Exception) {
                null
            }
        }
    }
}

/**
 * DNS header flags constants.
 */
internal object DNSFlags {
    /** Query/Response bit */
    const val QR_QUERY = 0x0000
    const val QR_RESPONSE = 0x8000

    /** Authoritative Answer bit */
    const val AA = 0x0400

    /** Truncation bit */
    const val TC = 0x0200

    /** Recursion Desired bit */
    const val RD = 0x0100

    /** Recursion Available bit */
    const val RA = 0x0080

    /** Standard query */
    const val STANDARD_QUERY = QR_QUERY

    /** Standard response with authoritative answer (mDNS) */
    const val STANDARD_RESPONSE = QR_RESPONSE or AA
}
