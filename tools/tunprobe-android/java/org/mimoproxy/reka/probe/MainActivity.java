package org.mimoproxy.reka.probe;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.widget.TextView;

/** Asks for VPN permission, then starts ProbeService. Extras: stack, hold. */
public final class MainActivity extends Activity {
    private static final int REQUEST_VPN = 1;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        TextView view = new TextView(this);
        view.setText("Reka TUN probe: waiting for VPN permission");
        setContentView(view);
        Intent prepare = VpnService.prepare(this);
        if (prepare != null) {
            startActivityForResult(prepare, REQUEST_VPN);
        } else {
            onActivityResult(REQUEST_VPN, RESULT_OK, null);
        }
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        if (request != REQUEST_VPN) {
            return;
        }
        TextView view = new TextView(this);
        if (result != RESULT_OK) {
            view.setText("VPN permission denied");
            setContentView(view);
            return;
        }
        Intent start = new Intent(this, ProbeService.class);
        start.putExtra("stack", getIntent().getStringExtra("stack"));
        start.putExtra("hold", getIntent().getIntExtra("hold", 10));
        startService(start);
        view.setText("Reka TUN probe running; see logcat tag RekaProbe");
        setContentView(view);
    }
}
