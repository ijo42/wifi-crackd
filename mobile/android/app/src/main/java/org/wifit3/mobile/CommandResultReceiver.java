package org.wifit3.mobile;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import org.json.JSONObject;

/** Non-exported explicit PendingIntent callback. Never logs stdout, tokens or Intent extras. */
public final class CommandResultReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        SharedPreferences p = TermuxLink.prefs(context);
        String expected=p.getString("pendingId",null);
        if (!TermuxLink.RESULT_ACTION.equals(intent.getAction()) || expected==null || intent.getData()==null
            || !("wifit3mobile-result:"+expected).equals(intent.getData().toString())
            || System.currentTimeMillis()-p.getLong("pendingAt",0)>120_000) return;
        String action=p.getString("pendingAction","");
        JSONObject outcome=new JSONObject();
        try {
            outcome.put("action",action);
            Bundle result=intent.getBundleExtra("result");
            if (result==null) throw new IllegalArgumentException("Termux не вернул результат команды.");
            String stdout=result.getString("stdout","");
            if (result.getInt("err",-1)!=-1 || result.getInt("exitCode",-1)!=0) {
                String message="Termux не выполнил команду. Проверьте установку модуля, RUN_COMMAND и allow-external-apps.";
                // Only our own well-formed protocol error is allowed into the UI, not arbitrary stdout/stderr.
                try {JSONObject error=new JSONObject(stdout.trim());if(TermuxLink.PROTOCOL.equals(error.optString("protocol")))message=error.optString("error",message);} catch(Exception ignored){}
                throw new IllegalArgumentException(message);
            }
            if (stdout.length()>8192) throw new IllegalArgumentException("Слишком большой ответ Termux.");
            JSONObject response=new JSONObject(stdout.trim());
            if (!TermuxLink.PROTOCOL.equals(response.optString("protocol")) || !action.equals(response.optString("action")))
                throw new IllegalArgumentException("Несовместимый модуль. Обновите установку в Termux.");
            String status=response.optString("status");
            if (!status.equals("running") && !status.equals("stopped")) throw new IllegalArgumentException("Неожиданное состояние модуля.");
            outcome.put("status",status);
            if (status.equals("running")) {
                String url=response.optString("url");
                if (!TermuxLink.validConnectionUrl(url)) throw new IllegalArgumentException("Некорректный локальный адрес модуля.");
                outcome.put("url",url).put("demo",response.optBoolean("demo"));
            }
        } catch (Exception e) {
            try {outcome.put("error",e.getMessage()==null?"Ошибка ответа Termux":e.getMessage().substring(0,Math.min(e.getMessage().length(),600)));}catch(Exception ignored){}
        }
        // Kept only until Activity resumes/consumes it. App backups are disabled.
        p.edit().remove("pendingId").remove("pendingAt").remove("pendingAction")
            .putString("result",outcome.toString()).putLong("resultAt",System.currentTimeMillis()).commit();
    }
}
