# Android library integration

The distribution supplies `jniLibs/arm64-v8a/libreka.so`, the Java `Native` class and the Kotlin wrapper. Minimum API: 26. Copy the native library into the host's `src/main/jniLibs/arm64-v8a` and compile the Java/Kotlin sources in the host module. Apply the packaged `consumer-rules.pro` to the host minifier. Keep `org.mimoproxy.reka.Native` and its nested `Host` interface when using R8; JNI names and callback signatures must not be obfuscated. Android SDK/NDK are build tools; no external system C/C++ runtime library is required.

The host owns `VpnService`, user consent, foreground service notification, lifecycle and `Builder` configuration. Construct the routes, addresses and DNS from the committed local network intent. Apply `addAllowedApplication` for `app-mode: include`, `addDisallowedApplication` for `exclude`, and neither for `all`. Packages missing from the device must be reported before activation. Set both IPv4/IPv6 routes only when both families are configured. Use a private `filesDir` state root. Configure an explicit DNS `nameserver` and `default-nameserver` (IP endpoint) for hostname resolution; libc/system DNS is not a protectable bootstrap contract on every Android image.

`Native.startVPN(root, profile, local, host, tun.fd)` borrows the descriptor during the synchronous call and duplicates it for the core. Close the host's original `ParcelFileDescriptor` after return, including failure; do not detach it. The library owns its duplicate. `Native.start` remains available for loopback-only hosts.

The host's `protect(fd)` must call `VpnService.protect(fd)` and return the result; a refusal fails the socket instead of sending it back into the VPN. Callbacks may arrive from any Go worker thread. `seal/open` must use authenticated encryption backed by Android Keystore; the plaintext passthrough in the short-lived **VPN test** host is not a production secret store. The separate library test verifies Keystore encryption. Marshal UI work from `onMessage` to the main thread.

`Host.findProcess(network, source, destination)` is optional. The supplied `ConnectionOwner` Java helper uses Android 10+'s `ConnectivityManager.getConnectionOwnerUid` while this app is the active VPN. Keep one helper in the service and delegate the callback to `owner.find(network, source, destination)`. It returns a package only for an observable UID with one visible package; unknown connections, shared UIDs, denied lookup and older Android versions return empty. Do not substitute the VPN app's own package when lookup fails. See the [Android API contract](https://developer.android.com/reference/android/net/ConnectivityManager#getConnectionOwnerUid(int,java.net.InetSocketAddress,java.net.InetSocketAddress)).

The callback receives the original socket endpoints: for TUN this includes the original packet destination, even when Fake IP routing has already recovered a domain. For a loopback proxy the peer is the local proxy listener. These are ownership-query endpoints, rather than a newly resolved outbound connection. Numeric endpoint parsing in the helper never performs hostname DNS.

On rule, selection, DNS or node changes, submit normal API transactions and retain the existing VPN interface. For changes requiring `Builder` reconstruction:

1. Read the revision and plan the local change. Show the interruption reported by the plan.
2. Establish the replacement VPN with the planned addresses/routes/app policy.
3. Call `Native.reconfigureVPN(handle, newTun.fd, commitRequestJson)` (or `Reka.reconfigureVPN`). Pass the **same** `CommitConfiguration` request with `base_revision`, `plan_hash` and a stable `operation_id`.
4. Close the host's original fd after return. Check both the transaction result and network runtime status. An OS/VPN failure after establishment can leave the host needing to stop and recreate its VPN; do not silently claim the old interface was restored.

The replacement entry duplicates the fd, applies the configuration through ConfigService, and explicitly rebuilds the runtime device when an idempotent/same-configuration commit does not create one. Ordinary API calls cannot rebuild an Android TUN without a fresh host descriptor. On `onRevoke`, stop the core and service. Do not call stop concurrently with a host rebuild; serialize the host lifecycle.

The binding takes one JSON document per call, without the socket transport's length prefix. Call `Hello` first. Subscribe for events through `Host.onMessage`; do not block the callback while waiting for another native call. All blocking calls belong off the UI thread.

The build compiles the shipped Java and Kotlin sources with a SHA-256-pinned Kotlin compiler. The Kotlin device mode verifies Hello, callbacks, Keystore encryption/decryption across restart, events, an intact connection across commit and idempotent retry.

Build and acceptance:

```sh
ANDROID_HOME=/path/to/sdk make android
python3 tools/android-runtime.py --serial YOUR_TEST_DEVICE
python3 tools/android-runtime.py --serial YOUR_TEST_DEVICE --skip-install --kotlin
python3 tools/android-runtime.py --serial YOUR_TEST_DEVICE --skip-install --vpn
# Authorized test device, connected over USB, with Wi-Fi initially on:
python3 tools/android-runtime.py --serial YOUR_USB_DEVICE --skip-install --vpn --full --network-cycle
```

The device must grant VPN consent first. `--grant-vpn` changes only this acceptance package's appop and is intended for dedicated test devices. Hosted CI cross-compiles the library; the separate self-hosted ARM64 workflow runs these device tests. `--skip-install` reuses the already installed APK for subsequent modes. `--full` additionally requests IPv4/IPv6 default routes and must only be used with explicit approval to capture the device's traffic. The test stops its VPN after success or failure. Short runs on a real API 37 device have passed; they do not establish uncharged background power consumption, long-duration memory behavior or 16 KiB-page compatibility on every device.

The VPN harness also verifies real UID/package rules against fresh HTTPS sockets, including a Fake IP destination. `--network-cycle` requires USB and initially enabled Wi-Fi. After the VPN announces readiness, it disables Wi-Fi for eight seconds, restores it, observes the underlying network loss/return, and checks fresh IPv4/IPv6 HTTPS and DNS without rebuilding the runtime or TUN. The phone may use cellular data during the interruption.

For idle power observation, first validate the harness with a short diagnostic:

```sh
python3 tools/android-power-runtime.py --serial YOUR_DEVICE --start --diagnostic --wait 180
# Separate, authorized uncharged measurement:
python3 tools/android-power-runtime.py --serial YOUR_DEVICE --start --minutes 30 --wait 0
```

The diagnostic permits charging and screen-on and never counts as power acceptance. A normal run first verifies the JNI handshake, actual dual-stack traffic and stop path, then waits for real charger removal and screen-off. It observes idle baseline and full VPN phases with the same target duration, then stops. It uses no wake lock or simulated battery unplug. Two exact wakeup alarms mark the phase boundaries after the test application receives Alarms & reminders access; reserve more than an hour for two 30-minute targets. JSON records actual durations, charge-counter readings, screen/charging state, CPU time, PSS and Go memory. Reconnecting a charger fails the measurement.

The ADB-only report URI is `content://org.mimoproxy.reka.test.reports/power`; an app-specific external copy at `/sdcard/Android/data/org.mimoproxy.reka.test/files/power-report.json` also permits retrieval on ROMs that block the provider while locked. The helper checks the current app PID to reject stale reports. A completed measurement does not automatically establish a power budget; retain both raw phases and note that wireless ADB can affect the baseline. Do not install a replacement APK during a measurement.

The uncharged idle A/B harness requires the Android **Alarms & reminders**
special access for the test APK (`SCHEDULE_EXACT_ALARM`). It checks this before
starting a formal measurement and schedules only the two phase-boundary wakeups;
it holds no wake lock. Some OEM ROMs defer inexact alarms for days, so a short
unlocked diagnostic cannot establish that locked phase switching works. A screen
activation or charger reconnect invalidates the formal run. The host observer
polls every 30 seconds by default, equally in both phases; record this observer
traffic when interpreting battery results.

After a formal uncharged idle A/B run completes, summarize its raw report:

```sh
python3 tools/android-power-analyze.py bin/android/power.json \
  --output bin/android/power-analysis.json
```

The analyzer checks real unplug/locked-screen conditions and monotonic phase
lengths, reports charge-counter resolution, whole-phone average current,
process CPU and Go/PSS memory separately. New harness reports record phase
start/deadline/end timestamps; older completed reports explicitly identify any
small sample-timestamp shortfall because samples are timestamped before PSS/JNI
work. JNI memory sampling forces GC and `FreeOSMemory`, and host polling runs in
both phases. A single sequential A/B can be affected by radio/background work
and temperature. Endpoint counter rounding is not a statistical confidence
interval. A power pass/fail stays unset unless an explicit
`--max-additional-ma` budget is supplied; the installed APK provenance must be
retained when evaluating later source changes. Restore any temporary exact-alarm
or OEM background permissions after collection.
