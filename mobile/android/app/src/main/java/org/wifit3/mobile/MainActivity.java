package org.wifit3.mobile;

import android.app.Activity;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Handler;
import android.os.Looper;
import android.widget.ScrollView;
import android.app.AlertDialog;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.webkit.JavascriptInterface;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;
import org.json.JSONObject;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/** Minimal Android host. Radio/USB and Python stay inside Termux, not inside WebView. */
public final class MainActivity extends Activity {
    private static final String HOME = TermuxLink.HOME;
    private static final int SAVE_REPORT = 41;
    private static final int SAVE_HASHES = 43;
    private WebView web;
    private String pendingReport;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private String requestedAction = "start";
    private boolean requestedDemo;
    private TextView commandStatus;
    private boolean awaiting;
    private final SharedPreferences.OnSharedPreferenceChangeListener results = (p,key) -> {
        if ("result".equals(key)) handler.post(() -> consumeResult());
    };

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        showControlPanel("Готов к подключению. Сканирование не запускается автоматически.");
        if(state!=null){requestedAction=state.getString("requestedAction","start");requestedDemo=state.getBoolean("requestedDemo");}
    }

    @Override protected void onResume() {
        super.onResume();TermuxLink.prefs(this).registerOnSharedPreferenceChangeListener(results);consumeResult();
    }
    @Override protected void onPause() {
        TermuxLink.prefs(this).unregisterOnSharedPreferenceChangeListener(results);super.onPause();
    }
    @Override protected void onSaveInstanceState(Bundle out) {
        out.putString("requestedAction",requestedAction);out.putBoolean("requestedDemo",requestedDemo);super.onSaveInstanceState(out);
    }

    private Button button(LinearLayout box, String label, Runnable action) {
        Button button = new Button(this);button.setText(label);button.setOnClickListener(v -> action.run());box.addView(button);return button;
    }
    private void showControlPanel(String status) {
        destroyWeb();
        LinearLayout box=new LinearLayout(this);box.setOrientation(LinearLayout.VERTICAL);
        int pad=(int)(24*getResources().getDisplayMetrics().density);box.setPadding(pad,pad*2,pad,pad);
        box.setBackgroundColor(Color.rgb(11,17,26));
        TextView title=new TextView(this);title.setTextColor(Color.rgb(102,226,188));title.setTextSize(25);title.setText("Wifit3 Mobile / Termux");box.addView(title);
        commandStatus=new TextView(this);commandStatus.setTextColor(Color.rgb(234,241,245));commandStatus.setTextSize(15);commandStatus.setText("\n"+status+"\n");box.addView(commandStatus);
        TextView scenario=new TextView(this);scenario.setTextColor(Color.rgb(102,226,188));scenario.setTextSize(13);scenario.setText("Основной сценарий: внешний USB-адаптер в Termux.");scenario.setPadding(0,pad,0,0);box.addView(scenario);
        Button startLive=button(box,"Запустить USB-режим в Termux",()->requestTermux("start",false));
        startLive.setTextSize(17);
        button(box,"Проверить и подключить работающий модуль",()->requestTermux("status",false));
        button(box,"Демо (диагностика, без USB)",()->requestTermux("start",true));
        button(box,"Остановить модуль Termux",()->confirmStop());
        button(box,"Настройка связи с Termux",()->showSetup());
        button(box,"Открыть Termux",()->openTermux());
        button(box,"Подключиться вручную по коду",()->openApp(HOME));
        TextView hint=new TextView(this);hint.setTextColor(Color.rgb(145,164,183));hint.setText("\nПассивный обзор; активный deauth и отправка хешей в Hashtopolis — только после согласия в интерфейсе. Кнопка запуска включает модуль, но не запускает радио: адаптер и разрешение выбираются в интерфейсе. Остановить модуль можно кнопкой «Завершить модуль» в веб-интерфейсе, «Стоп модуль» здесь или wifit3-mobile-service stop в Termux.");box.addView(hint);
        ScrollView scroll=new ScrollView(this);scroll.addView(box);setContentView(scroll);
    }
    private void setStatus(String text) { if(commandStatus!=null)commandStatus.setText("\n"+text+"\n"); }
    private void requestTermux(String action, boolean demo) {
        if(awaiting){setStatus("Ожидается ответ Termux. Не повторяйте запуск.");return;}
        try{getPackageManager().getPackageInfo("com.termux",0);}catch(PackageManager.NameNotFoundException e){showControlPanel("Termux не установлен. Сначала выполните настройку.");return;}
        requestedAction=action;requestedDemo=demo;
        if(checkSelfPermission(TermuxLink.PERMISSION)!=PackageManager.PERMISSION_GRANTED){
            new AlertDialog.Builder(this).setTitle("Разрешить связь с Termux?")
                .setMessage("Android запросит RUN_COMMAND: это разрешает приложению запускать команды в среде Termux. Здесь используются только фиксированные команды модуля Wifit3 Mobile. Также нужен allow-external-apps=true в Termux; см. настройку.")
                .setPositiveButton("Запросить",(d,w)->requestPermissions(new String[]{TermuxLink.PERMISSION},42))
                .setNegativeButton("Отмена",null).show();return;
        }
        executeTermux();
    }
    private void executeTermux() {
        try {
            awaiting=true;setStatus("Ожидается ответ Termux…");TermuxLink.execute(this,requestedAction,requestedDemo);
            final String pendingId=TermuxLink.prefs(this).getString("pendingId", "");
            handler.postDelayed(()->{if(awaiting && pendingId.equals(TermuxLink.prefs(this).getString("pendingId",null))){awaiting=false;showControlPanel("Termux не ответил за 45 секунд. Результат неизвестен. Проверьте разрешение, allow-external-apps и установку модуля, затем используйте проверку статуса. Не запускайте второй сервер вручную.");}},45_000);
        }catch(Exception e){awaiting=false;showControlPanel("Не удалось обратиться к Termux. Проверьте RUN_COMMAND и настройку внешних приложений.");}
    }
    @Override public void onRequestPermissionsResult(int code,String[] permissions,int[] grants){
        super.onRequestPermissionsResult(code,permissions,grants);
        if(code==42){if(grants.length>0 && grants[0]==PackageManager.PERMISSION_GRANTED)executeTermux();else showControlPanel("Разрешение Termux не выдано. Доступен ручной запуск и ввод кода.");}
    }
    private void consumeResult() {
        SharedPreferences p=TermuxLink.prefs(this);String raw=p.getString("result",null);if(raw==null)return;
        long at=p.getLong("resultAt",0);p.edit().remove("result").remove("resultAt").apply();awaiting=false;
        if(System.currentTimeMillis()-at>120_000){showControlPanel("Ответ Termux устарел. Проверьте статус ещё раз.");return;}
        try{
            JSONObject result=new JSONObject(raw);
            if(result.has("error")){showControlPanel(result.getString("error"));return;}
            if("running".equals(result.optString("status")) && TermuxLink.validConnectionUrl(result.optString("url"))){openApp(result.getString("url"));}
            else{destroyWeb();showControlPanel("Управляемый модуль остановлен. Можно запустить новую сессию.");}
        }catch(Exception e){showControlPanel("Некорректный ответ. Обновите модуль Termux.");}
    }
    private void confirmStop() {
        new AlertDialog.Builder(this).setTitle("Остановить модуль?")
            .setMessage("Приём будет остановлен, USB освобождён, локальное соединение закрыто.")
            .setPositiveButton("Остановить",(d,w)->{showControlPanel("Остановка модуля…");requestTermux("stop",false);})
            .setNegativeButton("Отмена",null).show();
    }
    private void showSetup(){
        new AlertDialog.Builder(this).setTitle("Первоначальная настройка")
            .setMessage("1. Установите Termux (0.109+) и Termux:API из совместимого источника.\n2. В распакованном проекте выполните в Termux:\nbash tools/install-termux.sh\n3. Если согласны разрешить внешние приложения:\nbash tools/enable-termux-link.sh\n4. Здесь нажмите запуск и выдайте разрешение RUN_COMMAND.\n\nНастройка не запускает сканирование. Не давайте RUN_COMMAND недоверенным приложениям. Ручное подключение по коду не требует этого разрешения.")
            .setPositiveButton("Открыть Termux",(d,w)->openTermux()).setNegativeButton("Закрыть",null).show();
    }
    private void openTermux(){Intent i=getPackageManager().getLaunchIntentForPackage("com.termux");if(i!=null)startActivity(i);else Toast.makeText(this,"Termux не установлен",Toast.LENGTH_LONG).show();}
    private void destroyWeb(){if(web!=null){web.removeJavascriptInterface("Android");web.destroy();web=null;}}

    private boolean allowed(Uri uri) {
        return "http".equals(uri.getScheme()) && "127.0.0.1".equals(uri.getHost())
            && uri.getPort() == 8765 && uri.getUserInfo() == null;
    }

    private void openApp(String connectionUrl) {
        destroyWeb();
        web = new WebView(this);
        web.setBackgroundColor(Color.rgb(11,17,26));
        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setAllowFileAccess(false);
        s.setAllowContentAccess(false);
        s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        s.setSupportMultipleWindows(false);
        s.setJavaScriptCanOpenWindowsAutomatically(false);
        s.setSafeBrowsingEnabled(true);
        android.webkit.CookieManager.getInstance().setAcceptCookie(false);
        web.addJavascriptInterface(new ExportBridge(), "Android");
        web.setWebViewClient(new WebViewClient() {
            @Override public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest req) {
                return !allowed(req.getUrl());
            }
            @Override public void onReceivedError(WebView view, WebResourceRequest req, WebResourceError err) {
                if (req.isForMainFrame()) runOnUiThread(() -> showOffline());
            }
        });
        LinearLayout root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);
        LinearLayout bar=new LinearLayout(this);bar.setOrientation(LinearLayout.HORIZONTAL);
        button(bar,"↔ Termux",()->showControlPanel("Управление модулем. Сканирование может продолжаться."));
        button(bar,"Стоп модуль",()->confirmStop());
        root.addView(bar);root.addView(web,new LinearLayout.LayoutParams(-1,0,1));
                // Target 35 enforces edge-to-edge: keep content out of system bars and IME.
        root.setOnApplyWindowInsetsListener((view, insets) -> {
            android.graphics.Insets bars = android.os.Build.VERSION.SDK_INT >= 30
                ? insets.getInsets(android.view.WindowInsets.Type.systemBars() | android.view.WindowInsets.Type.ime()) : null;
            if (bars != null) view.setPadding(bars.left,bars.top,bars.right,bars.bottom);
            else view.setPadding(insets.getSystemWindowInsetLeft(),insets.getSystemWindowInsetTop(),insets.getSystemWindowInsetRight(),insets.getSystemWindowInsetBottom());
            return insets;
        });
        setContentView(root);web.loadUrl(connectionUrl);
    }

    private void showOffline() {
        showControlPanel("Связь с модулем потеряна. Состояние приёма неизвестно. Проверьте статус Termux; не запускайте второй экземпляр вручную.");
    }

    /** Only capabilities exposed to the fixed, local origin: user-mediated document export (survey JSON, hc22000 text). */
    public final class ExportBridge {
        @JavascriptInterface public void saveReport(String json) {
            if (json == null || json.length() > 2_000_000) return;
            try {
                JSONObject parsed = new JSONObject(json);
                if (!"wifit3-mobile/survey-v1".equals(parsed.optString("format"))) return;
                parsed.getJSONArray("networks");
            } catch (Exception e) { return; }
            saveDocument(json, "application/json", "wifi-survey.json", SAVE_REPORT);
        }
        @JavascriptInterface public void saveHashes(String text) {
            if (text == null || text.length() > 2_000_000) return;
            int ok = 0;
            for (String line : text.split("\n")) {
                String t = line.trim();
                if (!t.isEmpty() && (t.startsWith("WPA*") || t.startsWith("PMKID*"))) ok++;
            }
            if (ok == 0 || ok != text.split("\n").length - (text.endsWith("\n") ? 1 : 0)) return;
            saveDocument(text, "text/plain", "wifit3-mobile.hc22000", SAVE_HASHES);
        }
        private void saveDocument(String content, String mime, String title, int requestCode) {
            runOnUiThread(() -> {
                if (pendingReport != null || web == null || web.getUrl() == null || !allowed(Uri.parse(web.getUrl()))) return;
                pendingReport = content;
                Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                intent.setType(mime);
                intent.putExtra(Intent.EXTRA_TITLE,title);
                try { startActivityForResult(intent, requestCode); }
                catch (Exception e) { pendingReport=null; Toast.makeText(MainActivity.this,"Нет приложения для сохранения документа",Toast.LENGTH_LONG).show(); }
            });
        }
    }

    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request,result,data);
        if (request != SAVE_REPORT && request != SAVE_HASHES) return;
        String report = pendingReport;
        pendingReport = null;
        if (result != RESULT_OK || data == null || data.getData() == null || report == null) return;
        try (OutputStream out = getContentResolver().openOutputStream(data.getData(),"wt")) {
            if (out == null) throw new java.io.IOException("No output stream");
            out.write(report.getBytes(StandardCharsets.UTF_8));
            Toast.makeText(this,request==SAVE_HASHES?"Хеши сохранены":"Снимок сохранён",Toast.LENGTH_SHORT).show();
        } catch (Exception e) { Toast.makeText(this,"Не удалось сохранить файл",Toast.LENGTH_LONG).show(); }
    }

    @Override public void onBackPressed() {
        if (web != null) web.evaluateJavascript("document.getElementById('details')?.close()",null);
        new AlertDialog.Builder(this).setTitle("Закрыть интерфейс?")
            .setMessage("Если сканирование запущено, оно продолжится в Termux. Для остановки сначала нажмите «Стоп».")
            .setPositiveButton("Закрыть",(d,w)->finish()).setNegativeButton("Остаться",null).show();
    }
    @Override protected void onDestroy() {
        handler.removeCallbacksAndMessages(null);
        destroyWeb();
        super.onDestroy();
    }
}
