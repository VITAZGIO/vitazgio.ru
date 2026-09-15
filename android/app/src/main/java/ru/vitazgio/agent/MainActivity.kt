package ru.vitazgio.agent

import android.Manifest
import android.app.DownloadManager
import android.app.Dialog
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.media.projection.MediaProjectionManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.Message
import android.view.View
import android.webkit.CookieManager
import android.webkit.PermissionRequest
import android.webkit.URLUtil
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import org.json.JSONObject
import ru.vitazgio.agent.databinding.ActivityMainBinding

/**
 * Оболочка: сайт живёт внутри приложения.
 *
 * Смысл не в «раз уж есть приложение»: (1) токен агента перестаёт вводиться
 * руками — сайт отдаёт его мосту сам; (2) кнопки следующих ступеней живут на
 * странице сайта, а не в нативном экране, значит нативного кода почти нет;
 * (3) правки сайта приезжают обычным деплоем, без пересборки APK.
 *
 * WebView — это НЕ Chrome. Всё, что в браузере работает само, здесь надо
 * включать руками, и каждый такой пункт ниже подписан: выбор файлов,
 * скачивание, отдельное окно плеера, кнопка «назад», куки, камера. Не
 * закрыть их сразу — значит получить оболочку хуже прежней PWA.
 */
class MainActivity : AppCompatActivity(), WebBridge.Host {

    companion object {
        private const val SITE = "https://vitazgio.ru"
        private const val START_PATH = "/cabinet"

        /** Открыть оболочку и сразу спросить согласие на захват экрана —
         *  по тычку в уведомление, когда телефон лежал в кармане. */
        const val ACTION_ASK_SCREEN = "ru.vitazgio.agent.ASK_SCREEN"

        /** Живое окно оболочки, если оно сейчас есть. Системный запрос на
         *  захват показывает только activity, а просьба приходит в службу —
         *  без этой ссылки ей некого попросить. Обнуляется в onDestroy,
         *  поэтому утечки окна тут нет. */
        @Volatile
        var live: MainActivity? = null
    }

    private lateinit var views: ActivityMainBinding
    private val ui = Handler(Looper.getMainLooper())

    /** Адрес главного кадра. Мост читает его из своего потока, поэтому поле
     *  volatile, а не вызов `webView.getUrl()` (тот только из UI-потока). */
    @Volatile
    private var mainFrameUrl: String = ""

    private var fileCallback: ValueCallback<Array<Uri>>? = null
    private lateinit var filePicker: ActivityResultLauncher<Intent>
    private var pendingPermission: PermissionRequest? = null
    private lateinit var mediaPermission: ActivityResultLauncher<Array<String>>
    private var popup: Dialog? = null
    private var failed = false
    private lateinit var projectionAsk: ActivityResultLauncher<Intent>

    private val strip = object : Runnable {
        override fun run() {
            views.strip.text = stripText()
            ui.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        views = ActivityMainBinding.inflate(layoutInflater)
        setContentView(views.root)

        filePicker = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            // Отдать callback ОБЯЗАТЕЛЬНО, даже при отмене: иначе поле выбора
            // файла на странице залипает навсегда и второй раз не открывается.
            fileCallback?.onReceiveValue(
                WebChromeClient.FileChooserParams.parseResult(result.resultCode, result.data)
            )
            fileCallback = null
        }

        mediaPermission = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { granted ->
            val request = pendingPermission
            pendingPermission = null
            if (request == null) return@registerForActivityResult
            if (granted.values.all { it }) request.grant(request.resources) else request.deny()
        }

        // Системный запрос «дать доступ к экрану». Подтверждение обязательно
        // на каждую сессию — Android 14 не разрешает его запомнить никаким
        // законным способом, и обходить это мы не будем.
        projectionAsk = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            val data = result.data
            if (result.resultCode != RESULT_OK || data == null) {
                AgentLog.add(this, "захват экрана не разрешили")
                return@registerForActivityResult
            }
            startService(
                Intent(this, AgentService::class.java)
                    .setAction(AgentService.ACTION_SCREEN_GRANT)
                    .putExtra(AgentService.EXTRA_RESULT_CODE, result.resultCode)
                    .putExtra(AgentService.EXTRA_RESULT_DATA, data)
            )
        }

        setupWeb(views.web)
        views.web.addJavascriptInterface(WebBridge(this), WebBridge.NAME)
        views.retry.setOnClickListener { reload() }

        // Полоска состояния — единственное, что оболочка рисует поверх сайта.
        // Долгий тычок открывает служебный экран с журналом: без него
        // разбирать ночные обрывы было бы не по чему.
        views.strip.setOnLongClickListener {
            startActivity(Intent(this, AgentActivity::class.java))
            true
        }

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                val open = popup
                when {
                    open != null -> open.dismiss()
                    views.web.canGoBack() -> views.web.goBack()
                    else -> finish()
                }
            }
        })

        if (savedInstanceState == null) {
            views.web.loadUrl(SITE + START_PATH)
        } else {
            views.web.restoreState(savedInstanceState)
        }

        if (intent?.action == ACTION_ASK_SCREEN) askProjection()

        if (AgentPrefs.enabled(this) && AgentPrefs.token(this).isNotBlank()) {
            AgentService.start(this)
        }
        Updater.checkOnStart(this)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        views.web.saveState(outState)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        // Тычок в уведомление «сайт просит экран» приходит сюда, когда окно
        // уже открыто: onCreate второй раз не позовут.
        if (intent.action == ACTION_ASK_SCREEN) askProjection()
    }

    override fun onResume() {
        super.onResume()
        live = this
        ui.post(strip)
    }

    override fun onStop() {
        if (live === this) live = null
        super.onStop()
    }

    /** Показать системный запрос на захват экрана. */
    fun askProjection() {
        val manager = getSystemService(Context.MEDIA_PROJECTION_SERVICE) as? MediaProjectionManager
        if (manager == null) {
            Toast.makeText(this, "Захват экрана недоступен", Toast.LENGTH_LONG).show()
            return
        }
        try {
            projectionAsk.launch(manager.createScreenCaptureIntent())
        } catch (e: Exception) {
            Toast.makeText(this, "Не вышло спросить про экран: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    override fun onPause() {
        ui.removeCallbacks(strip)
        // Без flush() сессия слетала бы при каждом убийстве процесса: куки
        // остаются в памяти WebView и на диск сами не ложатся.
        CookieManager.getInstance().flush()
        super.onPause()
    }

    override fun onDestroy() {
        if (live === this) live = null
        popup?.dismiss()
        views.web.destroy()
        super.onDestroy()
    }

    // ---- Настройка WebView --------------------------------------------------

    private fun setupWeb(web: WebView) {
        val settings = web.settings
        settings.javaScriptEnabled = true
        settings.domStorageEnabled = true
        settings.databaseEnabled = true
        // Музыка должна заводиться без тычка в плеер на каждой странице —
        // иначе мини-плеер сайта не подхватит трек при переходе.
        settings.mediaPlaybackRequiresUserGesture = false
        // Отдельное окно плеера (/player/pop) сайт открывает через
        // window.open. Без этих двух строк WebView такие окна молча глотает.
        settings.setSupportMultipleWindows(true)
        settings.javaScriptCanOpenWindowsAutomatically = true
        settings.loadWithOverviewMode = true
        settings.useWideViewPort = true
        // Файлам с диска телефона внутри страницы делать нечего.
        settings.allowFileAccess = false
        settings.allowContentAccess = false
        settings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
        settings.userAgentString = settings.userAgentString + " VGShell/" + BuildConfig.VERSION_CODE

        val cookies = CookieManager.getInstance()
        cookies.setAcceptCookie(true)
        cookies.setAcceptThirdPartyCookies(web, true)

        web.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                val url = request.url
                if (isOurs(url)) return false
                // Чужая ссылка уходит в системный браузер: внутри оболочки ей
                // делать нечего, а мост там всё равно молчит.
                return try {
                    startActivity(Intent(Intent.ACTION_VIEW, url).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                    true
                } catch (e: ActivityNotFoundException) {
                    true
                }
            }

            override fun onPageStarted(view: WebView, url: String, favicon: android.graphics.Bitmap?) {
                mainFrameUrl = url
            }

            override fun doUpdateVisitedHistory(view: WebView, url: String, isReload: Boolean) {
                mainFrameUrl = url
            }

            override fun onPageFinished(view: WebView, url: String) {
                mainFrameUrl = url
                if (!failed) showOffline(null)
            }

            override fun onReceivedError(
                view: WebView,
                request: WebResourceRequest,
                error: WebResourceError,
            ) {
                // Картинка не загрузилась — не повод закрывать весь сайт
                // заглушкой. Ругаемся только на главный кадр.
                if (!request.isForMainFrame) return
                failed = true
                showOffline(error.description?.toString())
            }
        }

        web.webChromeClient = object : WebChromeClient() {
            override fun onShowFileChooser(
                view: WebView,
                callback: ValueCallback<Array<Uri>>,
                params: FileChooserParams,
            ): Boolean {
                fileCallback?.onReceiveValue(null)
                fileCallback = callback
                return try {
                    // createIntent() уже учёл accept и multiple со страницы —
                    // свой intent собирать не нужно.
                    filePicker.launch(params.createIntent())
                    true
                } catch (e: ActivityNotFoundException) {
                    fileCallback = null
                    false
                }
            }

            override fun onPermissionRequest(request: PermissionRequest) {
                val needed = request.resources.mapNotNull {
                    when (it) {
                        PermissionRequest.RESOURCE_VIDEO_CAPTURE -> Manifest.permission.CAMERA
                        PermissionRequest.RESOURCE_AUDIO_CAPTURE -> Manifest.permission.RECORD_AUDIO
                        else -> null
                    }
                }
                if (needed.isEmpty()) {
                    request.deny()
                    return
                }
                val missing = needed.filter {
                    ContextCompat.checkSelfPermission(this@MainActivity, it) != PackageManager.PERMISSION_GRANTED
                }
                if (missing.isEmpty()) {
                    request.grant(request.resources)
                    return
                }
                pendingPermission = request
                mediaPermission.launch(missing.toTypedArray())
            }

            override fun onCreateWindow(
                view: WebView,
                isDialog: Boolean,
                isUserGesture: Boolean,
                resultMsg: Message,
            ): Boolean = openPopup(resultMsg)

            override fun onCloseWindow(window: WebView) {
                popup?.dismiss()
            }
        }

        // Любое скачивание: файл из дропа, zip папки, APK с /app. Куку
        // подкладываем руками — DownloadManager качает своим процессом и о
        // сессии WebView ничего не знает, а всё это закрыто login_required.
        web.setDownloadListener { url, userAgent, disposition, mimeType, _ ->
            downloadFile(url, userAgent, disposition, mimeType)
        }
    }

    /** Окно плеера: настоящее второе окно WebView в диалоге. Просто открыть
     *  адрес в том же окне нельзя — сайт рассчитывает, что звук в новом окне
     *  живёт отдельно от навигации по страницам. */
    private fun openPopup(resultMsg: Message): Boolean {
        val child = WebView(this)
        val settings = child.settings
        settings.javaScriptEnabled = true
        settings.domStorageEnabled = true
        settings.mediaPlaybackRequiresUserGesture = false
        child.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                if (isOurs(request.url)) return false
                return try {
                    startActivity(Intent(Intent.ACTION_VIEW, request.url).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                    true
                } catch (e: ActivityNotFoundException) {
                    true
                }
            }
        }
        child.webChromeClient = object : WebChromeClient() {
            override fun onCloseWindow(window: WebView) {
                popup?.dismiss()
            }
        }
        child.setDownloadListener { url, userAgent, disposition, mimeType, _ ->
            downloadFile(url, userAgent, disposition, mimeType)
        }

        val dialog = Dialog(this, android.R.style.Theme_Black_NoTitleBar)
        dialog.setContentView(child)
        dialog.setOnDismissListener {
            child.destroy()
            popup = null
        }
        dialog.show()
        popup = dialog

        val transport = resultMsg.obj as WebView.WebViewTransport
        transport.webView = child
        resultMsg.sendToTarget()
        return true
    }

    private fun downloadFile(url: String, userAgent: String?, disposition: String?, mimeType: String?) {
        val name = URLUtil.guessFileName(url, disposition, mimeType)
        try {
            val request = DownloadManager.Request(Uri.parse(url))
                .addRequestHeader("Cookie", CookieManager.getInstance().getCookie(url) ?: "")
                .addRequestHeader("User-Agent", userAgent ?: "")
                .setMimeType(mimeType)
                .setTitle(name)
                .setDestinationInExternalPublicDir(android.os.Environment.DIRECTORY_DOWNLOADS, name)
                .setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
            val manager = getSystemService(Context.DOWNLOAD_SERVICE) as DownloadManager
            val id = manager.enqueue(request)
            note("качаю $name")
            // Своя же сборка — единственное скачивание, после которого есть
            // что предложить: поставить.
            if (name.endsWith(".apk", ignoreCase = true)) Updater.installWhenReady(this, id)
            Toast.makeText(this, "Качаю: $name", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, "Не вышло скачать: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun isOurs(url: Uri): Boolean {
        val scheme = url.scheme?.lowercase()
        if (scheme != "https" && scheme != "http") return false
        val host = url.host?.lowercase() ?: return false
        return host == "vitazgio.ru" || host.endsWith(".vitazgio.ru")
    }

    private fun reload() {
        failed = false
        showOffline(null)
        views.web.loadUrl(SITE + START_PATH)
    }

    private fun showOffline(why: String?) {
        views.offline.visibility = if (why == null) View.GONE else View.VISIBLE
        if (why != null) views.offlineWhy.text = why
        if (why == null) failed = false
    }

    private fun stripText(): String {
        val status = AgentState.status
        val since = AgentState.connectedSince
        return if (since > 0) {
            val minutes = (System.currentTimeMillis() - since) / 60000
            "агент: $status · $minutes мин"
        } else {
            "агент: $status"
        }
    }

    // ---- WebBridge.Host -----------------------------------------------------

    override fun currentUrl(): String = mainFrameUrl

    override fun statusJson(): String = JSONObject()
        .put("app", BuildConfig.VERSION_CODE)
        .put("hasToken", AgentPrefs.token(this).isNotBlank())
        .put("connected", AgentState.connectedSince > 0)
        .put("status", AgentState.status)
        .toString()

    override fun saveAgentToken(token: String) {
        AgentPrefs.save(this, AgentPrefs.server(this), token)
        AgentPrefs.setEnabled(this, true)
        ui.post {
            askNotifications()
            AgentService.start(this)
        }
    }

    override fun startScreen() {
        ui.post { askProjection() }
    }

    override fun stopScreen() {
        startService(Intent(this, AgentService::class.java).setAction(AgentService.ACTION_SCREEN_STOP))
    }

    override fun note(text: String) {
        AgentLog.add(this, text)
    }

    private fun askNotifications() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val granted = ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
        if (granted != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 2)
        }
    }
}
