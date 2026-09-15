package ru.vitazgio.agent

import android.app.Activity
import android.content.Intent
import android.database.Cursor
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import android.webkit.CookieManager
import android.widget.Toast
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okio.BufferedSink
import okio.source
import java.util.concurrent.TimeUnit

/**
 * Приём «Поделиться» — то, что у PWA делал `share_target` из манифеста.
 *
 * Внутри оболочки манифест никто не читает, поэтому системное меню отправки
 * ловится обычным intent-filter'ом, а файл уходит на тот же серверный приёмник
 * `/share-target`, что и у PWA, и так же падает в папку Download дропа.
 *
 * Куку берём у WebView: приёмник за паролем кабинета, а своей сессии у этой
 * активности нет. Не вошли — сервер отправит на главную, и по конечному
 * адресу это видно (на /drop он уводит только при удаче).
 */
class ShareActivity : Activity() {

    private val client = OkHttpClient.Builder()
        .callTimeout(10, TimeUnit.MINUTES)     // видео с телефона бывают тяжёлыми
        .build()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val uris = collectUris(intent)
        val text = listOfNotNull(
            intent.getStringExtra(Intent.EXTRA_SUBJECT),
            intent.getStringExtra(Intent.EXTRA_TEXT),
        ).filter { it.isNotBlank() }

        if (uris.isEmpty() && text.isEmpty()) {
            Toast.makeText(this, "Нечего отправлять", Toast.LENGTH_SHORT).show()
            finish()
            return
        }

        Toast.makeText(this, "Отправляю в дроп…", Toast.LENGTH_SHORT).show()
        Thread { send(uris, text) }.start()
        // Экрана у этой активности нет: она прозрачная и закрывается сразу,
        // отправка живёт своим потоком. Стоять и смотреть на индикатор посреди
        // чужого приложения незачем.
        finish()
    }

    private fun collectUris(intent: Intent): List<Uri> = when (intent.action) {
        Intent.ACTION_SEND -> listOfNotNull(extra(intent, Intent.EXTRA_STREAM))
        Intent.ACTION_SEND_MULTIPLE -> extras(intent, Intent.EXTRA_STREAM)
        else -> emptyList()
    }

    @Suppress("DEPRECATION")
    private fun extra(intent: Intent, key: String): Uri? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(key, Uri::class.java)
        } else {
            intent.getParcelableExtra(key)
        }

    @Suppress("DEPRECATION")
    private fun extras(intent: Intent, key: String): List<Uri> =
        (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableArrayListExtra(key, Uri::class.java)
        } else {
            intent.getParcelableArrayListExtra<Uri>(key)
        }).orEmpty()

    private fun send(uris: List<Uri>, text: List<String>) {
        val server = AgentPrefs.server(this).trimEnd('/')
        val body = MultipartBody.Builder().setType(MultipartBody.FORM)
        uris.forEach { uri -> body.addFormDataPart("files", nameOf(uri), streamBody(uri)) }
        text.forEach { body.addFormDataPart("text", it) }

        val request = Request.Builder()
            .url("$server/share-target")
            .header("Cookie", CookieManager.getInstance().getCookie(server) ?: "")
            .post(body.build())
            .build()

        val outcome = try {
            client.newCall(request).execute().use { response ->
                // Приёмник в конце уводит на /drop. Не вошли — сервер отправит
                // на главную, и это единственный способ отличить одно от другого.
                val landed = response.request.url.encodedPath
                when {
                    !response.isSuccessful -> "сервер ответил ${response.code}"
                    landed.startsWith("/drop") -> null
                    else -> "сайт не пустил — зайди в кабинет в приложении"
                }
            }
        } catch (e: Exception) {
            e.message ?: "не вышло отправить"
        }

        val count = uris.size
        runOnUiThread {
            if (outcome == null) {
                AgentLog.add(this, "«Поделиться»: отправлено файлов — $count")
                Toast.makeText(this, "В дропе, папка Download", Toast.LENGTH_SHORT).show()
            } else {
                AgentLog.add(this, "«Поделиться» не вышло: $outcome")
                Toast.makeText(this, outcome, Toast.LENGTH_LONG).show()
            }
        }
    }

    /** Имя как в галерее, а не «content://…/1234». */
    private fun nameOf(uri: Uri): String {
        var cursor: Cursor? = null
        try {
            cursor = contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
            if (cursor != null && cursor.moveToFirst()) {
                val name = cursor.getString(0)
                if (!name.isNullOrBlank()) return name
            }
        } catch (e: Exception) {
            // имени нет — обойдёмся запасным
        } finally {
            cursor?.close()
        }
        return uri.lastPathSegment?.substringAfterLast('/') ?: "файл"
    }

    /** Тело запроса читает файл потоком: тянуть видео целиком в память
     *  телефона ради отправки незачем. */
    private fun streamBody(uri: Uri): RequestBody = object : RequestBody() {
        override fun contentType() =
            (contentResolver.getType(uri) ?: "application/octet-stream").toMediaTypeOrNull()

        override fun writeTo(sink: BufferedSink) {
            contentResolver.openInputStream(uri)?.use { stream ->
                sink.writeAll(stream.source())
            }
        }
    }
}
