package org.wifit3.mobile;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Build;
import java.util.UUID;

/** Fixed-command adapter for the documented Termux RUN_COMMAND API (Termux >= 0.109). */
public final class TermuxLink {
    public static final String PERMISSION = "com.termux.permission.RUN_COMMAND";
    public static final String PREFS = "termux-link";
    public static final String RESULT_ACTION = "org.wifit3.mobile.TERMUX_RESULT";
    public static final String PROTOCOL = "wifit3-mobile/termux-v1";
    public static final String HOME = "http://127.0.0.1:8765/";
    private TermuxLink() {}

    public static SharedPreferences prefs(Context c) { return c.getSharedPreferences(PREFS,Context.MODE_PRIVATE); }

    public static void execute(Context c, String action, boolean demo) {
        if (!action.equals("start") && !action.equals("status") && !action.equals("stop"))
            throw new IllegalArgumentException("Unsupported command");
        String id = UUID.randomUUID().toString();
        SharedPreferences p = prefs(c);
        p.edit().putString("pendingId",id).putString("pendingAction",action)
            .putLong("pendingAt",System.currentTimeMillis()).remove("result").commit();
        Intent callback = new Intent(c,CommandResultReceiver.class).setAction(RESULT_ACTION)
            .setData(Uri.parse("wifit3mobile-result:"+id));
        int flags = PendingIntent.FLAG_ONE_SHOT | PendingIntent.FLAG_CANCEL_CURRENT;
        // Termux needs to fill in result extras; the target and data are already explicit.
        if (Build.VERSION.SDK_INT >= 31) flags |= PendingIntent.FLAG_MUTABLE;
        PendingIntent pi = PendingIntent.getBroadcast(c,id.hashCode(),callback,flags);
        Intent run = new Intent("com.termux.RUN_COMMAND");
        run.setClassName("com.termux","com.termux.app.RunCommandService");
        run.putExtra("com.termux.RUN_COMMAND_PATH","/data/data/com.termux/files/usr/bin/wifit3-mobile-service");
        run.putExtra("com.termux.RUN_COMMAND_ARGUMENTS",demo && action.equals("start") ? new String[]{"start","--demo"} : new String[]{action});
        run.putExtra("com.termux.RUN_COMMAND_WORKDIR","/data/data/com.termux/files/home");
        run.putExtra("com.termux.RUN_COMMAND_BACKGROUND",true);
        run.putExtra("com.termux.RUN_COMMAND_BACKGROUND_CUSTOM_LOG_LEVEL","0");
        run.putExtra("com.termux.RUN_COMMAND_COMMAND_LABEL","Wifit3 Mobile · passive survey");
        run.putExtra("com.termux.RUN_COMMAND_PENDING_INTENT",pi);
        try {
            if(c.startService(run)==null) throw new IllegalStateException("Termux не принял команду");
        } catch (RuntimeException e) {
            pi.cancel();p.edit().remove("pendingId").remove("pendingAt").remove("pendingAction").apply();throw e;
        }
    }

    public static boolean validConnectionUrl(String url) {
        if (url==null || url.length()>140) return false;
        Uri uri=Uri.parse(url);
        String fragment=uri.getFragment();
        return "http".equals(uri.getScheme()) && "127.0.0.1".equals(uri.getHost()) && uri.getPort()==8765
            && uri.getUserInfo()==null && uri.getQuery()==null && "/".equals(uri.getPath())
            && fragment!=null && fragment.matches("[A-Za-z0-9_-]{43}");
    }
}
