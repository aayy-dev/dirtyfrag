package df.root;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.os.PowerManager;
import android.util.Log;

/**
 * Headless activity that starts the exploit and finishes immediately — no
 * confirmation, no expert-mode gate. Intended for Tasker or any automation
 * tool that can fire an intent at boot:
 *
 * <pre>am start -a df.root.action.AUTO_ROOT</pre>
 *
 * <p>This exists because Samsung's One UI broadcast allowlist sometimes
 * prevents {@link BootReceiver} from receiving BOOT_COMPLETED at all. An
 * automation tool that launches an activity sidesteps that restriction
 * entirely: activity starts are not subject to the broadcast allowlist.
 *
 * <p>Safe to call when BootReceiver is also enabled — {@code ExploitRunner.run}
 * is synchronized and checks {@code /dev/df} internally, so the slower caller
 * becomes a no-op. Unlike BootReceiver, this activity never disables the
 * receiver component on failure: the two paths are independent.
 */
public class AutoRootActivity extends Activity implements IReporter {
    private static final String TAG = "dfroot";

    @Override
    public void report(String msg) {
        Log.i(TAG, msg.trim());
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        if (D2Writer.suPresent()) {
            Log.i(TAG, "autoroot-activity: su already on path, device is rooted");
            finish();
            return;
        }
        if (RootState.hooked()) {
            Log.i(TAG, "autoroot-activity: hook mutex taken, exploit cannot run again this boot");
            finish();
            return;
        }

        final Context deCtx = createDeviceProtectedStorageContext();
        String suManager = deCtx.getSharedPreferences(ExploitRunner.PREFS_NAME, MODE_PRIVATE)
                .getString(ExploitRunner.PREF_SU_MANAGER, null);
        if (suManager == null) {
            Log.i(TAG, "autoroot-activity: no SU manager selected");
            finish();
            return;
        }

        boolean autoSoftReboot = deCtx.getSharedPreferences(ExploitRunner.PREFS_NAME, MODE_PRIVATE)
                .getBoolean("auto_soft_reboot", false);
        deCtx.getSharedPreferences(ExploitRunner.PREFS_NAME, MODE_PRIVATE)
                .edit().putBoolean(ExploitRunner.PREF_SOFT_REBOOT, autoSoftReboot).commit();

        PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
        PowerManager.WakeLock wl = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "dfroot:autoroot");
        wl.acquire();

        Log.i(TAG, "autoroot-activity: starting exploit");
        try {
            new Thread(() -> {
                try {
                    int rc = ExploitRunner.run(deCtx, this);
                    Log.i(TAG, "autoroot-activity: exploit rc=" + rc);
                } catch (Exception e) {
                    Log.e(TAG, "autoroot-activity: exploit exception", e);
                } finally {
                    wl.release();
                    runOnUiThread(this::finish);
                }
            }, "dfroot-autoroot").start();
        } catch (Throwable t) {
            wl.release();
            Log.e(TAG, "autoroot-activity: failed to start exploit thread", t);
            finish();
        }
    }
}
