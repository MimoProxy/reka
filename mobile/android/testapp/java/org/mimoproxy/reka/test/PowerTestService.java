package org.mimoproxy.reka.test;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.VpnService;
import android.os.BatteryManager;
import android.os.Debug;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.util.AtomicFile;
import android.util.Log;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import org.json.JSONArray;
import org.json.JSONObject;
import org.mimoproxy.reka.Native;

/** Dedicated idle A/B acceptance. No wake lock, artificial unplug or battery reset.
 * Waits for real unplug, then measures baseline and full VPN with equal targets.
 * Sampling can be delayed by suspend; reports use actual elapsed time.
 */
public final class PowerTestService extends VpnService {
    private volatile boolean cancelled;
    private final java.util.concurrent.atomic.AtomicBoolean running = new java.util.concurrent.atomic.AtomicBoolean();
    private long handle;
    private boolean diagnostic;
    private int phaseSeconds;
    private final Object boundary = new Object();
    private static volatile PowerTestService active;
    private final JSONObject report = new JSONObject();
    private final JSONArray phases = new JSONArray();

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        int minutes = intent == null ? 30 : intent.getIntExtra("minutes", 30);
        if (minutes < 1 || minutes > 720) { stopSelf(); return START_NOT_STICKY; }
        if (!running.compareAndSet(false, true)) return START_NOT_STICKY;
        diagnostic = intent != null && intent.getBooleanExtra("diagnostic", false);
        phaseSeconds = diagnostic ? Math.max(5, Math.min(60, intent.getIntExtra("seconds", 15))) : minutes * 60;
        active = this;
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel("power-test", "Reka idle acceptance", NotificationManager.IMPORTANCE_LOW));
        startForeground(15, new Notification.Builder(this, "power-test")
                .setContentTitle("Reka idle A/B acceptance: unplug USB")
                .setSmallIcon(android.R.drawable.ic_lock_lock).build());
        new Thread(() -> run(minutes), "reka-idle-acceptance").start();
        return START_NOT_STICKY;
    }

    private void run(int minutes) {
        try {
            report.put("requested_minutes_per_phase", minutes).put("phases", phases)
                    .put("pid", android.os.Process.myPid())
                    .put("phase_target_seconds", phaseSeconds).put("diagnostic", diagnostic)
                    .put("measurement_kind", diagnostic ? "harness_diagnostic" : "uncharged_ab")
                    .put("timing", diagnostic ? "diagnostic inexact boundary alarms" : "two exact phase-boundary wakeups; no held wake lock")
                    .put("wake_lock", false).put("artificial_unplug", false)
                    .put("version", BuildVersion.VERSION).put("state", "waiting_for_unplug");
            save();
            AlarmManager alarms = getSystemService(AlarmManager.class);
            boolean exact = android.os.Build.VERSION.SDK_INT < 31 || alarms.canScheduleExactAlarms();
            report.put("exact_alarm_permission", exact); save();
            if (!diagnostic && !exact) throw new Exception("Enable Alarms & reminders for Reka library test before uncharged measurement");
            // Exercise the full JNI handshake and stop path before asking the
            // user to wait through either measurement phase.
            startKernel(); Native.stop(handle); handle = 0;
            report.put("preflight_passed", true); save();
            long waitUntil = SystemClock.elapsedRealtime() + 10 * 60_000;
            while (!diagnostic && plugged() != 0 && !cancelled && SystemClock.elapsedRealtime() < waitUntil) Thread.sleep(1000);
            if (!diagnostic && plugged() != 0) throw new Exception("real USB/charger unplug was not observed within 10 minutes");
            if (cancelled) throw new Exception("cancelled before measurement");
            report.put("state", "waiting_for_screen_off"); save();
            long screenDeadline = SystemClock.elapsedRealtime() + 5 * 60_000;
            while (!diagnostic && getSystemService(android.os.PowerManager.class).isInteractive() && !cancelled && SystemClock.elapsedRealtime() < screenDeadline) Thread.sleep(1000);
            if (!diagnostic && getSystemService(android.os.PowerManager.class).isInteractive()) throw new Exception("screen did not turn off");
            phase("baseline", minutes);
            startKernel();
            phase("vpn", minutes);
            Native.stop(handle); handle = 0;
            Thread.sleep(1000);
            report.put("after_stop", sample()).put("state", "complete").put("measurement_complete", true);
            report.put("power_budget_passed", JSONObject.NULL);
        } catch (Throwable error) {
            try { report.put("state", "failed").put("error", error.toString()); } catch (Exception ignored) {}
        } finally {
            if (handle != 0) { Native.stop(handle); handle = 0; }
            try { save(); } catch (Exception error) { Log.e("RekaPowerTest", "report", error); }
            active = null;
            stopForeground(STOP_FOREGROUND_REMOVE);
            stopSelf();
        }
    }

    private void startKernel() throws Exception {
            String profile = "schema-version: 1\nlog: {level: error}\ndns:\n nameserver: [223.5.5.5]\n default-nameserver: [223.5.5.5]\n proxy-server-nameserver: [223.5.5.5]\nrules: [{id: final, match: {all: true}, outbound: direct}]\n";
            String local = "network:\n mode: tun\n tun:\n  dns-hijack: true\n  address6: 'fdfe:dcba:9876::1/126'\n";
            ParcelFileDescriptor fd = new Builder().setSession("Reka idle power acceptance")
                    .setMtu(1500).addAddress("172.19.0.1", 30).addAddress("fdfe:dcba:9876::1", 126)
                    .addRoute("0.0.0.0", 0).addRoute("::", 0).addDnsServer("172.19.0.2").establish();
            if (fd == null) throw new Exception("VPN consent missing");
            try {
                handle = Native.startVPN(new File(getFilesDir(), "power-" + System.nanoTime()).getPath(), profile, local,
                        new Native.Host() {
                            public boolean protect(int fd) { return PowerTestService.this.protect(fd); }
                            public byte[] seal(byte[] value) { return value; }
                            public byte[] open(byte[] value) { return value; }
                            public void onMessage(String value) {}
                        }, fd.getFd());
            } finally { fd.close(); }
            if (handle == 0) throw new Exception(Native.lastError());
            JSONObject hello = new JSONObject(Native.call(handle, "{\"id\":1,\"method\":\"Hello\",\"params\":{\"versions\":[1]}}"));
            if (hello.has("error")) throw new Exception(hello.toString());
            JSONObject status = new JSONObject(Native.call(handle, "{\"id\":2,\"method\":\"GetStatus\"}"));
            if (status.has("error") || status.getJSONObject("result").has("start_error")) throw new Exception(status.toString());
            if (!status.getJSONObject("result").getJSONObject("runtime").getJSONObject("network").getString("state").equals("Running")) throw new Exception("VPN not Running");
            Exception last = null;
            for (int attempt = 0; attempt < 12; attempt++) {
                try {
                    report.put("preflight_probe", "IPv4");
                    VpnTestService.https("223.5.5.5");
                    report.put("preflight_probe", "IPv6");
                    VpnTestService.https("2400:3200::1");
                    report.put("preflight_probe", "dualstack_passed");
                    return;
                } catch (java.io.IOException transientRoute) { last = transientRoute; Thread.sleep(500); }
            }
            throw new Exception("VPN route did not become ready: " + report.optString("preflight_probe"), last);
    }

    private void phase(String name, int minutes) throws Exception {
        report.put("state", name);
        JSONArray samples = new JSONArray();
        JSONObject phase = new JSONObject().put("name", name).put("samples", samples);
        phases.put(phase);
        long start = SystemClock.elapsedRealtime();
        long deadline = start + phaseSeconds * 1000L;
        AlarmManager alarms = getSystemService(AlarmManager.class);
        PendingIntent alarm = PendingIntent.getBroadcast(this, 19,
                new Intent(this, PowerBoundaryReceiver.class), PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        if (diagnostic) alarms.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, deadline, alarm);
        else alarms.setExactAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, deadline, alarm);
        try {
        do {
            if (cancelled) throw new Exception("VPN revoked or service cancelled");
            if (!diagnostic && plugged() != 0) throw new Exception("charger reconnected during measurement");
            JSONObject observed = sample();
            if (!diagnostic && observed.getBoolean("screen_interactive")) throw new Exception("screen activated during measurement");
            samples.put(observed); save();
            long remaining = deadline - SystemClock.elapsedRealtime();
            if (remaining <= 0) break;
            synchronized (boundary) {
                remaining = deadline - SystemClock.elapsedRealtime();
                if (remaining > 0) boundary.wait(Math.min(30_000, remaining));
            }
        } while (true);
        } finally { alarms.cancel(alarm); alarm.cancel(); }
        JSONObject first = samples.getJSONObject(0), last = samples.getJSONObject(samples.length() - 1);
        long elapsed = last.getLong("elapsed_ms") - first.getLong("elapsed_ms");
        phase.put("actual_elapsed_ms", elapsed);
        if (!diagnostic && !first.isNull("charge_uah") && !last.isNull("charge_uah") && elapsed > 0) {
            long used = first.getLong("charge_uah") - last.getLong("charge_uah");
            phase.put("charge_used_uah", used).put("mean_current_ma", used * 3600.0 / elapsed);
        }
        save();
    }

    static void signalBoundary() {
        PowerTestService service = active;
        if (service != null) synchronized (service.boundary) { service.boundary.notifyAll(); }
    }

    private int plugged() {
        Intent battery = registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        return battery == null ? -1 : battery.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1);
    }

    private JSONObject sample() throws Exception {
        BatteryManager battery = getSystemService(BatteryManager.class);
        Intent state = registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        JSONObject sample = new JSONObject().put("elapsed_ms", SystemClock.elapsedRealtime())
                .put("wall_ms", System.currentTimeMillis()).put("plugged", plugged())
                .put("screen_interactive", getSystemService(android.os.PowerManager.class).isInteractive())
                .put("pss_kib", Debug.getPss()).put("process_cpu_ms", android.os.Process.getElapsedCpuTime())
                .put("go", new JSONObject(Native.memStats()));
        int charge = battery.getIntProperty(BatteryManager.BATTERY_PROPERTY_CHARGE_COUNTER);
        sample.put("charge_uah", charge == Integer.MIN_VALUE ? JSONObject.NULL : charge);
        if (state != null) sample.put("level", state.getIntExtra(BatteryManager.EXTRA_LEVEL, -1))
                .put("temperature_deci_c", state.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1));
        return sample;
    }

    private void save() throws Exception {
        AtomicFile file = new AtomicFile(new File(getFilesDir(), "power-report.json"));
        FileOutputStream stream = file.startWrite();
        try {
            stream.write(report.toString(2).getBytes(StandardCharsets.UTF_8));
            file.finishWrite(stream);
        } catch (Exception error) { file.failWrite(stream); throw error; }
        // The app-specific external copy also lets ADB collect the fixed,
        // non-secret report on ROMs that block provider access while locked.
        File external = getExternalFilesDir(null);
        if (external != null) {
            AtomicFile copy = new AtomicFile(new File(external, "power-report.json"));
            FileOutputStream output = copy.startWrite();
            try { output.write(report.toString(2).getBytes(StandardCharsets.UTF_8)); copy.finishWrite(output); }
            catch (Exception error) { copy.failWrite(output); throw error; }
        }
        Log.i("RekaPowerTest", report.optString("state") + " phases=" + phases.length());
    }

    @Override public void onRevoke() { cancelled = true; signalBoundary(); }
    @Override public void onDestroy() { cancelled = true; signalBoundary(); super.onDestroy(); }
}
