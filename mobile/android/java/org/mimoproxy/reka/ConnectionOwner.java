package org.mimoproxy.reka;

import android.content.Context;
import android.net.ConnectivityManager;
import android.os.Build;
import android.system.OsConstants;
import org.json.JSONObject;
import java.net.InetAddress;
import java.net.InetSocketAddress;

/** Socket ownership lookup for an active VpnService (Android 10+).
 * Unknown ownership returns an empty object; a shared UID has no package path.
 * The caller must pass numeric packet endpoints, never a resolved hostname.
 */
public final class ConnectionOwner {
    private final ConnectivityManager manager;
    private final Context context;

    public ConnectionOwner(Context context) {
        this.context = context.getApplicationContext();
        this.manager = this.context.getSystemService(ConnectivityManager.class);
    }

    public String find(String network, String source, String destination) {
        String value = findProcessInfo(network, source, destination);
        if (value.isEmpty()) return "";
        try { return new JSONObject(value).optString("path", ""); }
        catch (Exception unavailable) { return ""; }
    }

    /** A shared UID remains useful for UID rules even when no unique package is known. */
    public String findProcessInfo(String network, String source, String destination) {
        if (Build.VERSION.SDK_INT < 29 || manager == null) return "{}";
        int protocol;
        if (network.equals("tcp")) protocol = OsConstants.IPPROTO_TCP;
        else if (network.equals("udp")) protocol = OsConstants.IPPROTO_UDP;
        else return "{}";
        try {
            int uid = manager.getConnectionOwnerUid(protocol, endpoint(source), endpoint(destination));
            if (uid < 0) return "{}";
            JSONObject info = new JSONObject().put("uid", uid);
            try {
                String[] packages = context.getPackageManager().getPackagesForUid(uid);
                if (packages != null && packages.length == 1 && packages[0] != null && !packages[0].isEmpty()) info.put("path", packages[0]);
            } catch (Exception packageUnavailable) {
                // Keep the OS-reported UID even when package visibility is restricted.
            }
            return info.toString();
        } catch (Exception unavailable) {
            return "{}";
        }
    }

    private static InetSocketAddress endpoint(String value) throws Exception {
        int split = value.lastIndexOf(':');
        if (split < 1) throw new IllegalArgumentException("missing port");
        String host = value.substring(0, split);
        if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
        // Reject hostnames before InetAddress can perform unprotected DNS.
        if (!(host.contains(":") && host.matches("[0-9a-fA-F:.]+"))
                && !host.matches("[0-9]+(\\.[0-9]+){3}")) throw new IllegalArgumentException("numeric IP required");
        return new InetSocketAddress(InetAddress.getByName(host), Integer.parseInt(value.substring(split + 1)));
    }
}
