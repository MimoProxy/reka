package org.mimoproxy.reka.probe;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Routes only the probe's test hosts into the VPN, so the rest of the
 * phone is unaffected, then hands the TUN fd to the Go probe.
 */
public final class ProbeService extends VpnService {
    private static final String TAG = "RekaProbe";

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        final String stack = intent != null && intent.getStringExtra("stack") != null
                ? intent.getStringExtra("stack") : "mixed";
        final int hold = intent != null ? intent.getIntExtra("hold", 10) : 10;
        new Thread(() -> runProbe(stack, hold), "reka-probe").start();
        return START_NOT_STICKY;
    }

    private void runProbe(String stack, int hold) {
        String report;
        try {
            ParcelFileDescriptor tun = new Builder()
                    .setSession("Reka TUN probe")
                    .setMtu(9000)
                    .addAddress("172.19.0.1", 30)
                    .addAddress("fdfe:dcba:9876::1", 126)
                    .addRoute("223.5.5.5", 32)
                    .addRoute("2400:3200::1", 128)
                    .establish();
            if (tun == null) {
                report = "FAIL: establish() returned null (permission revoked?)";
            } else {
                Log.i(TAG, "established, stack=" + stack);
                report = Native.run(this, tun.detachFd(), stack, hold);
            }
        } catch (Throwable t) {
            report = "FAIL: " + t;
        }
        for (String line : report.split("\n")) {
            Log.i(TAG, line);
        }
        try (FileOutputStream out = new FileOutputStream(new File(getFilesDir(), "report-" + stack + ".txt"))) {
            out.write(report.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            Log.w(TAG, "write report", e);
        }
        Log.i(TAG, "done stack=" + stack);
        stopSelf();
    }
}
