package org.mimoproxy.reka;

/**
 * JNI binding of the Reka kernel (libreka.so). Messages are the control
 * API's JSON documents, the same ones the desktop socket carries. Prefer
 * the Kotlin wrapper {@code Reka}.
 */
public final class Native {
    static {
        System.loadLibrary("reka");
    }

    /** Implemented by the host app. Methods may be called on any thread. */
    public interface Host {
        /** VpnService.protect(fd): keep the kernel's own socket out of the VPN. */
        boolean protect(int fd);

        /** Encrypt a secret at rest (for example with an Android Keystore key). */
        byte[] seal(byte[] plain);

        /** Decrypt what seal returned. */
        byte[] open(byte[] sealed);

        /** Receives event messages. */
        void onMessage(String message);
    }

    /**
     * Starts a kernel on stateRoot (the app's private directory). profile and
     * local seed revision 1 when the directory is empty; pass null otherwise.
     * Returns a handle, or 0 with the reason in lastError().
     */
    public static native long start(String stateRoot, String profile, String local, Host host);

    public static native String lastError();

    /** Handles one request message and returns its response message. */
    public static native String call(long handle, String request);

    public static native void stop(long handle);

    /** Go runtime memory figures, as JSON. */
    public static native String memStats();

    private Native() {}
}
