package org.mimoproxy.reka.test;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** Two phase-boundary wakeups, not a held wake lock or battery exemption. */
public final class PowerBoundaryReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        PowerTestService.signalBoundary();
    }
}
