package org.mimoproxy.reka.test;

import android.app.Activity;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mimoproxy.reka.Native;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Runs the library acceptance on a device: loopback proxy through the
 * kernel, a long connection kept intact across hot updates, secrets
 * sealed by an Android Keystore key, memory figures. Results go to logcat
 * (tag RekaTest) and to the screen.
 */
public class MainActivity extends Activity {
    private static final String TAG = "RekaTest";
    private static final int PROXY_PORT = 17990;
    private final StringBuilder report = new StringBuilder();
    private final AtomicInteger events = new AtomicInteger();
    private final AtomicLong ids = new AtomicLong();
    private long handle;
    private TextView view;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        view = new TextView(this);
        setContentView(view);
        if(getIntent().getBooleanExtra("kotlin",false)){new Thread(()->{try{log(KotlinAcceptance.run(this));log("RESULT PASS");}catch(Throwable error){Log.e(TAG,"Kotlin acceptance",error);log("FAIL "+error);log("RESULT FAIL");}},"reka-kotlin-test").start();return;}
        if(getIntent().getBooleanExtra("vpn",false) || getIntent().getIntExtra("battery-minutes",0)>0){android.content.Intent permission=android.net.VpnService.prepare(this);if(permission!=null)startActivityForResult(permission,17);else startVPNTest();}else new Thread(this::runTest).start();
    }

    private void startVPNTest(){int minutes=getIntent().getIntExtra("battery-minutes",0);if(minutes>0){view.setText("Idle A/B acceptance: unplug USB, keep Wi-Fi, turn the screen off. Baseline and full VPN: at least "+minutes+" minutes each.");startService(new android.content.Intent(this,PowerTestService.class).putExtra("minutes",minutes).putExtra("diagnostic",getIntent().getBooleanExtra("diagnostic",false)).putExtra("seconds",getIntent().getIntExtra("seconds",15)));}else startService(new android.content.Intent(this,VpnTestService.class).putExtra("full",getIntent().getBooleanExtra("full",false)).putExtra("network-cycle",getIntent().getBooleanExtra("network-cycle",false)));}
    @Override protected void onActivityResult(int request,int result,android.content.Intent data){super.onActivityResult(request,result,data);if(request==17 && result==RESULT_OK)startVPNTest();}

    private void log(String line) {
        Log.i(TAG, line);
        report.append(line).append('\n');
        runOnUiThread(() -> view.setText(report.toString()));
    }

    private JSONObject call(String method, JSONObject params) throws Exception {
        JSONObject req = new JSONObject().put("id", ids.incrementAndGet()).put("method", method);
        if (params != null) req.put("params", params);
        JSONObject resp = new JSONObject(Native.call(handle, req.toString()));
        if (resp.has("error")) throw new Exception(method + ": " + resp.getJSONObject("error"));
        return resp.optJSONObject("result");
    }

    private static SecretKey key() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (ks.containsAlias("reka-test")) return (SecretKey) ks.getKey("reka-test", null);
        KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        kg.init(new KeyGenParameterSpec.Builder("reka-test", KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build());
        return kg.generateKey();
    }

    private final Native.Host host = new Native.Host() {
        @Override public boolean protect(int fd) { return true; }

        @Override public byte[] seal(byte[] plain) {
            try {
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.ENCRYPT_MODE, key());
                byte[] iv = c.getIV(), ct = c.doFinal(plain);
                byte[] out = Arrays.copyOf(iv, iv.length + ct.length);
                System.arraycopy(ct, 0, out, iv.length, ct.length);
                return out;
            } catch (Exception e) {
                Log.e(TAG, "seal", e);
                return null;
            }
        }

        @Override public byte[] open(byte[] sealed) {
            try {
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128, sealed, 0, 12));
                return c.doFinal(sealed, 12, sealed.length - 12);
            } catch (Exception e) {
                Log.e(TAG, "open", e);
                return null;
            }
        }

        @Override public void onMessage(String message) { events.incrementAndGet(); }
    };

    private static void deleteTree(File f) {
        File[] kids = f.listFiles();
        if (kids != null) for (File k : kids) deleteTree(k);
        f.delete();
    }

    /** Echo server standing in for a remote site. */
    private static ServerSocket echoServer() throws Exception {
        ServerSocket ss = new ServerSocket();
        ss.bind(new InetSocketAddress("127.0.0.1", 0));
        new Thread(() -> {
            while (true) {
                try {
                    Socket s = ss.accept();
                    new Thread(() -> {
                        try (Socket c = s) {
                            byte[] buf = new byte[65536];
                            InputStream in = c.getInputStream();
                            OutputStream out = c.getOutputStream();
                            for (int n; (n = in.read(buf)) > 0; ) out.write(buf, 0, n);
                        } catch (Exception ignored) {
                        }
                    }).start();
                } catch (Exception e) {
                    return;
                }
            }
        }).start();
        return ss;
    }

    private void runTest() {
        boolean ok = true;
        try {
            File root = new File(getFilesDir(), "reka-test");
            deleteTree(root);
            String profile = "schema-version: 1\ndns: {nameserver: [223.5.5.5], default-nameserver: [223.5.5.5]}\n"
                    + "outbounds:\n  - {id: alt, type: direct}\n"
                    + "groups:\n  - {id: proxy, type: select, members: [direct, alt]}\n"
                    + "rules:\n  - {id: blocked, match: {domain-suffix: blocked.test}, outbound: reject}\n"
                    + "  - {id: final, match: {all: true}, outbound: proxy}\n";
            String local = "listeners:\n  - {id: mixed, type: mixed, listen: \"127.0.0.1:" + PROXY_PORT + "\"}\n";
            long t0 = System.nanoTime();
            handle = Native.start(root.getPath(), profile, local, host);
            if (handle == 0) throw new Exception("start: " + Native.lastError());
            log(String.format("start: %.1f ms", (System.nanoTime() - t0) / 1e6));
            JSONObject hello=call("Hello", new JSONObject().put("versions", new JSONArray().put(1)).put("client", "testapp"));
            if(!hello.getString("server").equals("reka/"+BuildVersion.VERSION))throw new Exception("library version mismatch: "+hello);
            log("API build version: "+hello.getString("server"));
            call("Subscribe", new JSONObject());

            ServerSocket echo = echoServer();
            Proxy proxy = new Proxy(Proxy.Type.SOCKS, new InetSocketAddress("127.0.0.1", PROXY_PORT));

            // Long connection through the proxy, verified byte for byte.
            Socket longConn = new Socket(proxy);
            longConn.connect(new InetSocketAddress("127.0.0.1", echo.getLocalPort()), 5000);
            longConn.setSoTimeout(10000);
            final long[] sent = {0};
            final boolean[] intact = {true};
            Random rnd = new Random(1);
            MessageDigest sentHash = MessageDigest.getInstance("SHA-256");
            MessageDigest gotHash = MessageDigest.getInstance("SHA-256");
            Thread reader = new Thread(() -> {
                try {
                    byte[] buf = new byte[65536];
                    InputStream in = longConn.getInputStream();
                    for (int n; (n = in.read(buf)) > 0; ) gotHash.update(buf, 0, n);
                } catch (Exception e) {
                    intact[0] = false;
                    Log.e(TAG, "long connection read", e);
                }
            });
            reader.start();
            OutputStream lout = longConn.getOutputStream();
            byte[] chunk = new byte[256 << 10];

            String gen0 = call("GetStatus", null).getJSONObject("runtime").optString("generation");
            for (int i = 0; i < 20; i++) {
                rnd.nextBytes(chunk);
                sentHash.update(chunk);
                lout.write(chunk);
                sent[0] += chunk.length;
                if (i == 5 || i == 12) {
                    String sel = i == 5 ? "alt" : "direct";
                    JSONObject st = call("GetStatus", null);
                    JSONObject res = call("CommitConfiguration", new JSONObject()
                            .put("base_revision", st.getLong("revision"))
                            .put("patch", new JSONArray().put(new JSONObject()
                                    .put("op", "set").put("path", "/groups/proxy/selected").put("value", sel))));
                    log("hot update (select " + sel + "): " + res.getString("state") + ", revision " + res.optLong("revision")
                            + ", generation " + res.optLong("generation"));
                    if (!"committed".equals(res.getString("state"))) ok = false;
                }
                Thread.sleep(50);
            }
            longConn.shutdownOutput();
            reader.join(15000);
            longConn.close();
            boolean same = intact[0] && MessageDigest.isEqual(sentHash.digest(), gotHash.digest());
            log("long connection across 2 hot updates: " + sent[0] + " bytes, " + (same ? "intact" : "BROKEN"));
            ok &= same;

            // A real HTTPS request through the proxy.
            try {
                HttpURLConnection http = (HttpURLConnection) new URL("https://www.baidu.com/").openConnection(proxy);
                http.setConnectTimeout(8000);
                http.setReadTimeout(8000);
                log("HTTPS via proxy: " + http.getResponseCode());
                http.disconnect();
            } catch (Exception e) {
                log("HTTPS via proxy failed (network?): " + e);
            }

            // Rejected by rule.
            try (Socket s = new Socket(proxy)) {
                s.connect(InetSocketAddress.createUnresolved("x.blocked.test", 80), 5000);
                s.getOutputStream().write(1);
                int r = s.getInputStream().read();
                log("blocked.test: connected, read " + r + " (expected refusal)");
                ok &= r < 0;
            } catch (Exception e) {
                log("blocked.test: refused (" + e.getClass().getSimpleName() + ")");
            }

            // Secrets go through the host's Keystore cipher.
            call("SetSecret", new JSONObject().put("name", "test/secret").put("value", "s3cret").put("apply", false));
            JSONArray names = call("ListSecrets", null).getJSONArray("names");
            byte[] file = java.nio.file.Files.readAllBytes(new File(root, "secrets/secrets.json").toPath());
            boolean sealed = names.length() == 1 && !new String(file).contains("s3cret");
            log("secret sealed by Keystore: " + sealed);
            ok &= sealed;

            JSONObject st = call("GetStatus", null);
            log("status: revision " + st.getLong("revision") + ", generation " + gen0 + " -> "
                    + st.getJSONObject("runtime").getLong("generation") + ", connections "
                    + st.getJSONObject("runtime").getInt("connections") + ", events received " + events.get());

            File lib = new File(getApplicationInfo().nativeLibraryDir, "libreka.so");
            log(String.format("libreka.so: %.1f MB", lib.length() / 1048576.0));
            Thread.sleep(10000);
            log("idle 10 s: " + Native.memStats());
            Native.stop(handle);
            echo.close();
            log("stopped");
        } catch (Throwable e) {
            ok = false;
            log("FAIL: " + e);
            Log.e(TAG, "test", e);
        }
        log(ok ? "RESULT PASS" : "RESULT FAIL");
    }
}
