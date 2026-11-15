package org.mimoproxy.reka.probe;

import android.net.VpnService;

final class Native {
    static {
        System.loadLibrary("tunprobe");
    }

    /** Runs the probe on the TUN fd; blocks for holdSeconds after the checks. */
    static native String run(VpnService service, int fd, String stack, int holdSeconds);

    private Native() {}
}
