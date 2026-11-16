package org.mimoproxy.reka.test;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** Two phase-boundary wakeups, exact alarms with user-granted permission; no held wake lock. */
public final class PowerBoundaryReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        PowerTestService.signalBoundary();
    }
}
