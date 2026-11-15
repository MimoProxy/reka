# Android library integration

The distribution supplies `jniLibs/arm64-v8a/libreka.so`, the Java `Native` class and the Kotlin wrapper. Minimum API: 26. Copy the native library into the host's `src/main/jniLibs/arm64-v8a` and compile the Java/Kotlin sources in the host module. Apply the packaged `consumer-rules.pro` to the host minifier. Keep `org.mimoproxy.reka.Native` and its nested `Host` interface when using R8; JNI names and callback signatures must not be obfuscated. Android SDK/NDK are build tools; no external system C/C++ runtime library is required.

The host owns `VpnService`, user consent, foreground service notification, lifecycle and `Builder` configuration. Construct the routes, addresses and DNS from the committed local network intent. Apply `addAllowedApplication` for `app-mode: include`, `addDisallowedApplication` for `exclude`, and neither for `all`. Packages missing from the device must be reported before activation. Set both IPv4/IPv6 routes only when both families are configured. Use a private `filesDir` state root. Configure an explicit DNS `nameserver` and `default-nameserver` (IP endpoint) for hostname resolution; libc/system DNS is not a protectable bootstrap contract on every Android image.

`Native.startVPN(root, profile, local, host, tun.fd)` borrows the descriptor during the synchronous call and duplicates it for the core. Close the host's original `ParcelFileDescriptor` after return, including failure; do not detach it. The library owns its duplicate. `Native.start` remains available for loopback-only hosts.

The host's `protect(fd)` must call `VpnService.protect(fd)` and return the result; a refusal fails the socket instead of sending it back into the VPN. Callbacks may arrive from any Go worker thread. `seal/open` must use authenticated encryption backed by Android Keystore; the plaintext passthrough in the short-lived **VPN test** host is not a production secret store. The separate library test verifies Keystore encryption. Marshal UI work from `onMessage` to the main thread.

`Host.findProcess(network, source, destination)` is optional. Resolve the owning UID (for example with `ConnectivityManager.getConnectionOwnerUid` where permitted), then return the corresponding package name; return an empty string when unknown. Reka does not guess a package. The callback's availability does not prove that every Android version permits lookup.

On rule, selection, DNS or node changes, submit normal API transactions and retain the existing VPN interface. For changes requiring `Builder` reconstruction:

1. Read the revision and plan the local change. Show the interruption reported by the plan.
2. Establish the replacement VPN with the planned addresses/routes/app policy.
3. Call `Native.reconfigureVPN(handle, newTun.fd, commitRequestJson)` (or `Reka.reconfigureVPN`). Pass the **same** `CommitConfiguration` request with `base_revision`, `plan_hash` and a stable `operation_id`.
4. Close the host's original fd after return. Check both the transaction result and network runtime status. An OS/VPN failure after establishment can leave the host needing to stop and recreate its VPN; do not silently claim the old interface was restored.

The replacement entry duplicates the fd, applies the configuration through ConfigService, and explicitly rebuilds the runtime device when an idempotent/same-configuration commit does not create one. Ordinary API calls cannot rebuild an Android TUN without a fresh host descriptor. On `onRevoke`, stop the core and service. Do not call stop concurrently with a host rebuild; serialize the host lifecycle.

The binding takes one JSON document per call, without the socket transport's length prefix. Call `Hello` first. Subscribe for events through `Host.onMessage`; do not block the callback while waiting for another native call. All blocking calls belong off the UI thread.

Build and acceptance:

```sh
ANDROID_HOME=/path/to/sdk make android
python3 tools/android-runtime.py --serial YOUR_TEST_DEVICE
python3 tools/android-runtime.py --serial YOUR_TEST_DEVICE --skip-install --vpn
```

The device must grant VPN consent first. `--grant-vpn` changes only this acceptance package's appop and is intended for dedicated test devices. Hosted CI cross-compiles the library; the separate self-hosted ARM64 workflow runs these device tests. `--skip-install` reuses the already installed APK for subsequent modes. `--full` additionally requests IPv4/IPv6 default routes and must only be used with explicit approval to capture the device's traffic. The test stops its VPN after success or failure. Short runs on a real API 37 device have passed; they do not establish uncharged background power consumption, long-duration memory behavior or 16 KiB-page compatibility on every device.
