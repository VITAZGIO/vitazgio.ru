package ru.vitazgio.agent

import android.app.DownloadManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.webkit.CookieManager
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.core.content.ContextCompat
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * Самообновление. Магазина в этой истории нет, поэтому без него каждая
 * правка нативной части означала бы «зайди на сайт, скачай, поставь руками».
 *
 * Сравниваем свою versionCode с `/api/app/version`, и если на сайте лежит
 * свежее — предлагаем поставить. Качаем с `/app`: он за паролем кабинета,
 * поэтому к запросу подкладывается кука WebView (у DownloadManager свой
 * процесс, сессии оболочки он не знает).
 */
object Updater {

    private val client = OkHttpClient.Builder()
        .callTimeout(20, TimeUnit.SECONDS)
        .build()

    private var offered = false

    fun checkOnStart(activity: MainActivity) {
        if (offered) return          // одного предложения за запуск довольно
        offered = true
        Thread {
            val server = AgentPrefs.server(activity).trimEnd('/')
            val token = AgentPrefs.token(activity)
            val request = Request.Builder()
                .url("$server/api/app/version")
                .header("Cookie", CookieManager.getInstance().getCookie(server) ?: "")
                .also { if (token.isNotBlank()) it.header("X-Agent-Token", token) }
                .build()
            val newest = try {
                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) return@Thread
                    JSONObject(response.body?.string().orEmpty()).optInt("version", 0)
                }
            } catch (e: Exception) {
                return@Thread
            }
            if (newest <= BuildConfig.VERSION_CODE) return@Thread
            activity.runOnUiThread { offer(activity, server, newest) }
        }.start()
    }

    private fun offer(activity: MainActivity, server: String, newest: Int) {
        if (activity.isFinishing) return
        AlertDialog.Builder(activity)
            .setTitle("Есть сборка $newest")
            .setMessage("Сейчас стоит ${BuildConfig.VERSION_CODE}. Скачать и поставить?")
            .setNegativeButton("Потом", null)
            .setPositiveButton("Обновить") { _, _ -> download(activity, server) }
            .show()
    }

    private fun download(activity: MainActivity, server: String) {
        if (!canInstall(activity)) {
            // Разрешение «ставить из этого источника» даёт только сам
            // человек и только в настройках — молча его не получить.
            Toast.makeText(activity, "Разреши установку из этого приложения и нажми ещё раз",
                Toast.LENGTH_LONG).show()
            try {
                activity.startActivity(
                    Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                        Uri.parse("package:${activity.packageName}"))
                )
            } catch (e: Exception) {
                // настроек нет — дальше человек разберётся сам
            }
            return
        }
        val url = "$server/app"
        try {
            val request = DownloadManager.Request(Uri.parse(url))
                .addRequestHeader("Cookie", CookieManager.getInstance().getCookie(server) ?: "")
                .setTitle("VG Агент")
                .setMimeType("application/vnd.android.package-archive")
                .setDestinationInExternalPublicDir(android.os.Environment.DIRECTORY_DOWNLOADS, "vg-agent.apk")
                .setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
            val manager = activity.getSystemService(Context.DOWNLOAD_SERVICE) as DownloadManager
            installWhenReady(activity, manager.enqueue(request))
            AgentLog.add(activity, "качаю обновление")
        } catch (e: Exception) {
            Toast.makeText(activity, "Не вышло скачать сборку: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun canInstall(context: Context): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.O || context.packageManager.canRequestPackageInstalls()

    /** Дождаться конца скачивания и предложить установку. Адрес файла берём
     *  у самого DownloadManager (content://) — своего FileProvider ради этого
     *  заводить не нужно. */
    fun installWhenReady(context: Context, downloadId: Long) {
        val appContext = context.applicationContext
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ignored: Context, intent: Intent) {
                val done = intent.getLongExtra(DownloadManager.EXTRA_DOWNLOAD_ID, -1)
                if (done != downloadId) return
                try {
                    appContext.unregisterReceiver(this)
                } catch (e: Exception) {
                    // уже снят — не беда
                }
                val manager = appContext.getSystemService(Context.DOWNLOAD_SERVICE) as DownloadManager
                val uri = manager.getUriForDownloadedFile(downloadId) ?: return
                if (!canInstall(appContext)) return
                val install = Intent(Intent.ACTION_VIEW)
                    .setDataAndType(uri, "application/vnd.android.package-archive")
                    .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
                try {
                    appContext.startActivity(install)
                } catch (e: Exception) {
                    AgentLog.add(appContext, "установку открыть не вышло: ${e.message}")
                }
            }
        }
        // Широковещание шлёт система, поэтому приёмник обязан быть
        // экспортируемым: с Android 14 регистрация без явного флага падает.
        ContextCompat.registerReceiver(
            appContext,
            receiver,
            IntentFilter(DownloadManager.ACTION_DOWNLOAD_COMPLETE),
            ContextCompat.RECEIVER_EXPORTED,
        )
    }
}
