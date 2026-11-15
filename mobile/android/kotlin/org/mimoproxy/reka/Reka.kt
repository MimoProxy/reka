package org.mimoproxy.reka

import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicLong

/** A control API error returned by the kernel. */
class RekaException(val code: String, message: String) : Exception(message)

/**
 * Thin Kotlin wrapper over [Native]. Calls block until the kernel answers;
 * run them off the main thread.
 *
 * ```
 * val reka = Reka.start(filesDir.resolve("reka").path, host = myHost)
 * val status = reka.call("GetStatus")
 * reka.call("CommitConfiguration", JSONObject()
 *     .put("base_revision", status.getLong("revision"))
 *     .put("patch", JSONArray().put(JSONObject()
 *         .put("op", "set").put("path", "/groups/proxy/selected").put("value", "hk"))))
 * ```
 */
class Reka private constructor(private val handle: Long) : AutoCloseable {
    private val ids = AtomicLong()

    /** Calls a control API method and returns its result object. */
    fun call(method: String, params: JSONObject? = null): JSONObject {
        val req = JSONObject().put("id", ids.incrementAndGet()).put("method", method)
        if (params != null) req.put("params", params)
        val resp = JSONObject(Native.call(handle, req.toString()))
        resp.optJSONObject("error")?.let { throw RekaException(it.optString("code"), it.optString("message")) }
        return resp.optJSONObject("result") ?: JSONObject()
    }

    /** Subscribes to events; they arrive through [Host.onEvent]. */
    fun subscribe(types: List<String> = emptyList()) {
        call("Subscribe", JSONObject().put("types", JSONArray(types)))
    }

    override fun close() = Native.stop(handle)

    /** What the host app provides. */
    interface Host {
        fun protect(fd: Int): Boolean
        fun seal(plain: ByteArray): ByteArray
        fun open(sealed: ByteArray): ByteArray
        fun onEvent(event: JSONObject) {}
    }

    companion object {
        /** Starts the kernel and negotiates the API version. */
        fun start(stateRoot: String, profile: String? = null, local: String? = null, host: Host): Reka {
            val native = object : Native.Host {
                override fun protect(fd: Int) = host.protect(fd)
                override fun seal(plain: ByteArray) = host.seal(plain)
                override fun open(sealed: ByteArray) = host.open(sealed)
                override fun onMessage(message: String) {
                    JSONObject(message).optJSONObject("event")?.let(host::onEvent)
                }
            }
            val handle = Native.start(stateRoot, profile, local, native)
            if (handle == 0L) throw RekaException("start", Native.lastError())
            return Reka(handle).also {
                it.call("Hello", JSONObject().put("versions", JSONArray(listOf(1))).put("client", "android"))
            }
        }
    }
}
