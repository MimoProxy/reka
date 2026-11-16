package org.mimoproxy.reka.test

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.json.JSONArray
import org.json.JSONObject
import org.mimoproxy.reka.Reka
import org.mimoproxy.reka.RekaException
import java.io.File
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.security.KeyStore
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Exercises the shipped Kotlin source, not a second control binding. */
object KotlinAcceptance {
    @JvmStatic fun run(context: Context): String {
        val root = File(context.filesDir, "kotlin-acceptance")
        root.deleteRecursively()
        val events = AtomicInteger()
        val sealed = AtomicInteger()
        val opened = AtomicInteger()
        val alias = "reka-kotlin-acceptance"
        fun key(): SecretKey {
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (store.containsAlias(alias)) return store.getKey(alias, null) as SecretKey
            return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
                init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
            }.generateKey()
        }
        val host = object : Reka.Host {
            override fun protect(fd: Int) = true
            override fun seal(plain: ByteArray): ByteArray {
                sealed.incrementAndGet()
                val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
                return cipher.iv + cipher.doFinal(plain)
            }
            override fun open(value: ByteArray): ByteArray {
                opened.incrementAndGet()
                return Cipher.getInstance("AES/GCM/NoPadding").apply {
                    init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, value.copyOfRange(0, 12)))
                }.doFinal(value, 12, value.size - 12)
            }
            override fun onEvent(event: JSONObject) { events.incrementAndGet() }
        }
        val port = ServerSocket(0).use { it.localPort }
        val profile = "schema-version: 1\nlog: {level: error}\noutbounds: [{id: unused, type: http, server: '127.0.0.1', port: 1, username: fixture, password: pending}]\nrules: [{id: final, match: {all: true}, outbound: direct}]\n"
        val local = "listeners: [{id: mixed, type: mixed, listen: '127.0.0.1:$port'}]\n"
        try {
            ServerSocket(0).use { echo ->
                Thread {
                    try { echo.accept().use { socket -> socket.getInputStream().copyTo(socket.getOutputStream()) } }
                    catch (_: Exception) { }
                }.apply { isDaemon = true; start() }
                Reka.start(root.path, profile, local, host).use { reka ->
                    check(reka.call("GetCapabilities").getInt("api_version") == 1)
                    reka.subscribe()
                    reka.call("SetSecret", JSONObject().put("name", "kotlin/test").put("value", "test-only-value").put("apply", false))
                    Socket(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", port))).use { connection ->
                        connection.connect(InetSocketAddress("127.0.0.1", echo.localPort), 5000)
                        connection.soTimeout = 5000
                        fun roundTrip() {
                            val expected = ByteArray(8192) { (it % 251).toByte() }
                            connection.getOutputStream().write(expected)
                            val actual = ByteArray(expected.size)
                            java.io.DataInputStream(connection.getInputStream()).readFully(actual)
                            check(expected.contentEquals(actual))
                        }
                        roundTrip()
                        val base = reka.call("GetStatus").getLong("revision")
                        val change = JSONObject().put("base_revision", base).put("patch", JSONArray().put(
                            JSONObject().put("op", "set").put("path", "/log/level").put("value", "warn")).put(
                            JSONObject().put("op", "set").put("path", "/outbounds/unused/password").put("value", "secret://kotlin/test")))
                        val plan = reka.call("PlanConfiguration", change)
                        change.put("plan_hash", plan.getString("plan_hash")).put("operation_id", "kotlin-commit")
                        val result = reka.call("CommitConfiguration", change)
                        check(result.getString("state") == "committed")
                        check(reka.call("CommitConfiguration", change).getLong("revision") == result.getLong("revision"))
                        roundTrip()
                        try { reka.call("NotAnAPI"); error("missing Kotlin exception") }
                        catch (expected: RekaException) { check(expected.code == "unknown_method") }
                        repeat(50) { if (events.get() == 0) Thread.sleep(20) }
                        check(events.get() > 0 && sealed.get() > 0)
                    }
                }
            }
            opened.set(0)
            Reka.start(root.path, host = host).use { check(it.call("GetStatus").getLong("revision") > 1) }
            check(opened.get() > 0)
            return JSONObject().put("kotlin_wrapper", "passed").put("long_connection_across_commit", true)
                .put("idempotent_retry", true).put("keystore_restart", true).put("events", events.get()).toString()
        } finally {
            root.deleteRecursively()
            KeyStore.getInstance("AndroidKeyStore").apply { load(null); if (containsAlias(alias)) deleteEntry(alias) }
        }
    }
}
