package ru.vitazgio.agent

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.Manifest
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.net.Uri
import android.os.PowerManager
import android.provider.Settings
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import androidx.core.content.ContextCompat
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * Единственное, что умеет приложение: соединиться и жить.
 *
 * Ни экрана, ни файлов, ни управления — это следующие ступени. Здесь только
 * постоянный исходящий вебсокет до /ws/agent и честный журнал того, что с ним
 * происходило ночью.
 */
class AgentService : Service() {

    companion object {
        const val ACTION_START = "ru.vitazgio.agent.START"
        const val ACTION_STOP = "ru.vitazgio.agent.STOP"

        /** Человек подтвердил захват экрана — activity передаёт согласие сюда. */
        const val ACTION_SCREEN_GRANT = "ru.vitazgio.agent.SCREEN_GRANT"
        const val ACTION_SCREEN_STOP = "ru.vitazgio.agent.SCREEN_STOP"
        const val EXTRA_RESULT_CODE = "result_code"
        const val EXTRA_RESULT_DATA = "result_data"

        private const val CHANNEL = "vg-agent"
        private const val NOTIFICATION_ID = 7
        // Просьба показать экран приходит с сайта, а подтвердить её можно
        // только руками на телефоне. Отдельный канал и погромче: это не
        // вывеска службы, а вопрос, на который ждут ответа.
        private const val ASK_CHANNEL = "vg-screen-ask"
        private const val ASK_NOTIFICATION_ID = 8
        private const val FILES_NOTIFICATION_ID = 9

        // Своё ping/pong поверх протокольного: сервер ждёт весточку не реже
        // раза в минуту, а промежуточные прокси любят резать «молчащие»
        // соединения раньше этого срока.
        private const val PING_SECONDS = 25L
        private const val BACKOFF_START_MS = 1_000L
        private const val BACKOFF_MAX_MS = 60_000L
        private const val HEARTBEAT_MS = 30 * 60 * 1000L

        fun start(context: Context) {
            val intent = Intent(context, AgentService::class.java).setAction(ACTION_START)
            context.startForegroundService(intent)
        }

        fun stop(context: Context) {
            context.startService(Intent(context, AgentService::class.java).setAction(ACTION_STOP))
        }
    }

    private lateinit var worker: HandlerThread
    private lateinit var handler: Handler
    private lateinit var client: OkHttpClient

    private var socket: WebSocket? = null
    private var backoff = BACKOFF_START_MS
    private var stopping = false
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    private var caster: ScreenCaster? = null
    private var files: FileAgent? = null
    private var audio: AudioCaster? = null

    private val reconnectTask = Runnable { connect() }
    private val heartbeatTask = object : Runnable {
        override fun run() {
            if (AgentState.connectedSince > 0) {
                val minutes = (System.currentTimeMillis() - AgentState.connectedSince) / 60000
                log("на связи уже $minutes мин")
            }
            handler.postDelayed(this, HEARTBEAT_MS)
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        worker = HandlerThread("vg-agent").apply { start() }
        handler = Handler(worker.looper)
        client = OkHttpClient.Builder()
            // Чтение без таймаута: сокет молчит часами и это норма.
            .readTimeout(0, TimeUnit.MILLISECONDS)
            .connectTimeout(15, TimeUnit.SECONDS)
            .pingInterval(PING_SECONDS, TimeUnit.SECONDS)
            .retryOnConnectionFailure(true)
            .build()
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            shutdown()
            return START_NOT_STICKY
        }
        if (intent?.action == ACTION_SCREEN_GRANT) {
            grantScreen(intent)
            return START_STICKY
        }
        if (intent?.action == ACTION_SCREEN_STOP) {
            caster?.stop()
            return START_STICKY
        }

        startForeground(NOTIFICATION_ID, notification(AgentState.status))
        if (!AgentState.running) {
            AgentState.running = true
            stopping = false
            log("служба запущена (версия ${BuildConfig.VERSION_CODE})")
            watchNetwork()
            handler.post(reconnectTask)
            handler.postDelayed(heartbeatTask, HEARTBEAT_MS)
        }
        // START_STICKY — просьба к системе поднять службу, если её всё-таки
        // прибили. Гарантии это не даёт (в том и вопрос ночного теста), но
        // шанс подняться самому стоит одной константы.
        return START_STICKY
    }

    override fun onDestroy() {
        shutdown()
        worker.quitSafely()
        super.onDestroy()
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        // Смахнули карточку из недавних — служба должна остаться. Именно это
        // и душат оболочки вроде HiOS, ради этого ночной тест и затеян.
        log("карточку приложения смахнули из недавних, служба продолжает работу")
        super.onTaskRemoved(rootIntent)
    }

    // ---- Соединение ---------------------------------------------------------

    private fun connect() {
        if (stopping) return
        val server = AgentPrefs.server(this)
        val token = AgentPrefs.token(this)
        if (token.isBlank()) {
            setStatus("нет токена — вбей его на экране")
            return
        }

        val url = wsUrl(server)
        if (url == null) {
            setStatus("адрес сервера непонятен: $server")
            return
        }

        AgentState.attempts += 1
        setStatus("подключаюсь…")

        // Короткий wake lock только на время рукопожатия: постоянный держать
        // нельзя (аккумулятор), а заснуть ровно посреди подключения — обидно.
        val power = getSystemService(Context.POWER_SERVICE) as PowerManager
        val wake = power.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "vg-agent:connect")
        wake.acquire(30_000)

        val request = Request.Builder().url(url).build()
        // Приняли нас или закрыли сразу — разница важная: закрытое без
        // «hello-ok» соединение почти всегда значит неверный токен, и без
        // этой пометки в журнале это выглядело бы как обрыв связи.
        var accepted = false
        socket = client.newWebSocket(request, object : WebSocketListener() {

            override fun onOpen(webSocket: WebSocket, response: Response) {
                releaseQuietly(wake)
                val hello = JSONObject()
                    .put("type", "hello")
                    .put("token", token)
                    .put("agent", "${Build.MANUFACTURER} ${Build.MODEL}")
                    .put("version", BuildConfig.VERSION_CODE)
                webSocket.send(hello.toString())
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                val type = try {
                    JSONObject(text).optString("type")
                } catch (e: Exception) {
                    ""
                }
                when (type) {
                    "hello-ok" -> {
                        accepted = true
                        backoff = BACKOFF_START_MS
                        AgentState.connectedSince = System.currentTimeMillis()
                        setStatus("на связи")
                        log("сервер принял (попытка ${AgentState.attempts})")
                    }
                    // Сервер сам проверяет, живы ли мы. Ответ обязателен:
                    // молчание дольше минуты он считает смертью.
                    "ping" -> webSocket.send(JSONObject().put("type", "pong").toString())

                    // Экран. Команд ровно пять и все узкие: «выполни строку»
                    // в протоколе нет и не будет.
                    "screen-start" -> askForScreen()
                    "screen-stop" -> {
                        // Без живого захвата звука всё равно не будет —
                        // гасим его сразу, а не оставляем висеть.
                        audio?.stop()
                        caster?.stop()
                    }
                    "screen-pause" -> caster?.pause()
                    "screen-resume" -> caster?.resume()
                    "screen-key" -> caster?.requestKeyFrame()

                    // Файлы телефона под готовой страницей /files сайта.
                    "fs" -> ensureFiles().handle(webSocket, JSONObject(text))

                    // Управление пальцем с ПК. Работает, только если человек
                    // сам включил службу спец-возможностей на телефоне.
                    "touch" -> handleTouch(webSocket, JSONObject(text))

                    // Звук телефона — тем же захватом, что и картинка.
                    "audio-start" -> startAudio(webSocket)
                    "audio-stop" -> audio?.stop()

                    // Неизвестный тип игнорируем, а не падаем и не толкуем
                    // наугад — сервер на той стороне делает ровно так же.
                }
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                // Двоичное от сайта бывает только одного рода: кусок файла,
                // который он в нас пишет.
                ensureFiles().handleFrame(bytes)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                releaseQuietly(wake)
                if (accepted) {
                    log("сервер закрыл соединение ($code ${reason.ifBlank { "без причины" }})")
                } else {
                    log("сервер не принял — скорее всего не тот токен")
                }
                scheduleReconnect()
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                releaseQuietly(wake)
                val why = response?.code?.let { "ответ $it" } ?: (t.message ?: t.javaClass.simpleName)
                log("соединение оборвалось: $why")
                scheduleReconnect()
            }
        })
    }

    // ---- Экран --------------------------------------------------------------

    private fun ensureCaster(): ScreenCaster {
        val existing = caster
        if (existing != null) return existing
        val fresh = ScreenCaster(
            context = this,
            send = { frame -> sendFrame(frame) },
            state = { running, paused, width, height, error ->
                sendJson(JSONObject()
                    .put("type", "screen-state")
                    .put("running", running)
                    .put("paused", paused)
                    .put("width", width)
                    .put("height", height)
                    .put("error", error))
                setStatus(if (running) "на связи · экран идёт" else "на связи")
                if (!running) hideAsk()
            },
            log = { text -> log(text) },
        )
        caster = fresh
        return fresh
    }

    /** Жест или кнопка с сайта. Отвечаем честно: служба не включена — так и
     *  говорим, чтобы страница не делала вид, будто нажатие прошло. */
    private fun handleTouch(socket: WebSocket, payload: JSONObject) {
        val touch = TouchService.live
        if (touch == null) {
            socket.send(JSONObject()
                .put("type", "touch-reply")
                .put("ok", false)
                .put("error", "Управление не включено: разреши службу спец-возможностей на телефоне.")
                .toString())
            return
        }
        val done = when (payload.optString("action")) {
            "tap", "long", "swipe" -> touch.gesture(
                payload.optString("action"),
                payload.optDouble("x", 0.0),
                payload.optDouble("y", 0.0),
                payload.optDouble("x2", 0.0),
                payload.optDouble("y2", 0.0),
                payload.optLong("ms", 0L),
            )
            "key" -> touch.key(payload.optString("name"))
            "text" -> touch.type(payload.optString("text"))
            "backspace" -> touch.backspace()
            else -> false
        }
        if (!done) {
            socket.send(JSONObject()
                .put("type", "touch-reply")
                .put("ok", false)
                .put("error", "Телефон не принял нажатие.")
                .toString())
        }
    }

    /** Звук требует разрешения на запись: Android считает захват системного
     *  звука записью, хотя микрофон тут ни при чём. Спросить его может только
     *  окно, поэтому без живой оболочки честно отвечаем отказом. */
    private fun startAudio(socket: WebSocket) {
        val granted = ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) ==
            PackageManager.PERMISSION_GRANTED
        if (!granted) {
            val screen = MainActivity.live
            if (screen != null) {
                screen.runOnUiThread { screen.askMicrophone() }
                socket.send(JSONObject()
                    .put("type", "audio-state").put("running", false)
                    .put("error", "Разреши запись звука на телефоне и нажми ещё раз.").toString())
            } else {
                socket.send(JSONObject()
                    .put("type", "audio-state").put("running", false)
                    .put("error", "Нужно разрешение на запись звука — открой приложение на телефоне.")
                    .toString())
            }
            return
        }
        // С Android 14 служба обязана объявить и тип microphone, пока идёт
        // захват звука, иначе система его оборвёт.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            try {
                startForeground(
                    NOTIFICATION_ID,
                    notification(AgentState.status),
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE or
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION or
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE,
                )
            } catch (e: Exception) {
                log("не вышло объявить службу записью звука: ${e.message}")
            }
        }
        ensureAudio().start(caster?.session())
    }

    private fun ensureAudio(): AudioCaster {
        val existing = audio
        if (existing != null) return existing
        val fresh = AudioCaster(
            send = { frame -> sendFrame(frame) },
            state = { running, error ->
                sendJson(JSONObject()
                    .put("type", "audio-state")
                    .put("running", running)
                    .put("error", error))
            },
            log = { text -> log(text) },
        )
        audio = fresh
        return fresh
    }

    private fun ensureFiles(): FileAgent {
        val existing = files
        if (existing != null) return existing
        val fresh = FileAgent(
            context = this,
            log = { text -> log(text) },
            askAccess = { showFilesAsk() },
        )
        files = fresh
        return fresh
    }

    private fun sendFrame(frame: ByteArray) {
        val open = socket ?: return
        // Двоичным сообщением, а не строкой: кадр — это байты H.264, и
        // любое текстовое кодирование раздуло бы его на треть.
        // toByteString, а не ByteString.of: в okio 3 старый вызов помечен
        // не предупреждением, а ошибкой компиляции — сборка на нём и легла.
        open.send(frame.toByteString(0, frame.size))
    }

    private fun sendJson(payload: JSONObject) {
        socket?.send(payload.toString())
    }

    /** Сайт попросил экран. Согласие даёт только человек и только на самом
     *  телефоне — обойти это нечем (Android 14 спрашивает каждую сессию). */
    private fun askForScreen() {
        if (caster?.isRunning == true) {
            caster?.resume()
            return
        }
        val screen = MainActivity.live
        if (screen != null) {
            log("прошу подтверждение захвата на экране")
            screen.runOnUiThread { screen.askProjection() }
            return
        }
        // Приложение не на переднем плане — запустить окно из фона Android
        // не даст. Поэтому кладём уведомление: тычок по нему откроет
        // оболочку и спросит согласие.
        log("телефон не в руках — положил уведомление с просьбой")
        showAsk()
    }

    private fun grantScreen(intent: Intent) {
        val code = intent.getIntExtra(EXTRA_RESULT_CODE, 0)
        @Suppress("DEPRECATION")
        val data: Intent? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(EXTRA_RESULT_DATA, Intent::class.java)
        } else {
            intent.getParcelableExtra(EXTRA_RESULT_DATA)
        }
        hideAsk()
        if (data == null) {
            log("согласия на захват нет")
            return
        }
        // С Android 14 служба обязана СНАЧАЛА стать foreground-службой с
        // типом mediaProjection и только потом брать саму проекцию.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            try {
                startForeground(
                    NOTIFICATION_ID,
                    notification(AgentState.status),
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE or
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION,
                )
            } catch (e: Exception) {
                log("не вышло объявить службу захватом экрана: ${e.message}")
            }
        }
        ensureCaster().start(code, data)
    }

    /** Уведомление «разреши доступ к файлам»: открывает тот самый экран
     *  настроек, где это разрешение и выдаётся — один раз и навсегда. */
    private fun showFilesAsk() {
        val settings = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                Uri.parse("package:$packageName"))
        } else {
            Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                Uri.parse("package:$packageName"))
        }.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val open = PendingIntent.getActivity(
            this, 2, settings,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val ask = Notification.Builder(this, ASK_CHANNEL)
            .setContentTitle("Нужен доступ к файлам")
            .setContentText("Нажми и разреши «доступ ко всем файлам»")
            .setSmallIcon(R.drawable.ic_agent)
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        getSystemService(NotificationManager::class.java)?.notify(FILES_NOTIFICATION_ID, ask)
    }

    private fun showAsk() {
        val open = PendingIntent.getActivity(
            this,
            1,
            Intent(this, MainActivity::class.java)
                .setAction(MainActivity.ACTION_ASK_SCREEN)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val ask = Notification.Builder(this, ASK_CHANNEL)
            .setContentTitle("Сайт просит показать экран")
            .setContentText("Нажми, чтобы подтвердить захват")
            .setSmallIcon(R.drawable.ic_agent)
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        getSystemService(NotificationManager::class.java)?.notify(ASK_NOTIFICATION_ID, ask)
    }

    private fun hideAsk() {
        getSystemService(NotificationManager::class.java)?.cancel(ASK_NOTIFICATION_ID)
    }

    private fun scheduleReconnect() {
        AgentState.connectedSince = 0
        socket = null
        if (stopping) return
        val delay = backoff
        // Нарастающая пауза: 1, 2, 4… до минуты. Без неё телефон без сети
        // молотил бы подключением и высадил аккумулятор за ночь.
        backoff = (backoff * 2).coerceAtMost(BACKOFF_MAX_MS)
        setStatus("нет связи, повтор через ${delay / 1000} с")
        handler.removeCallbacks(reconnectTask)
        handler.postDelayed(reconnectTask, delay)
    }

    private fun reconnectNow(reason: String) {
        if (stopping) return
        log("сеть вернулась ($reason) — подключаюсь сразу")
        backoff = BACKOFF_START_MS
        socket?.cancel()
        socket = null
        handler.removeCallbacks(reconnectTask)
        handler.post(reconnectTask)
    }

    private fun watchNetwork() {
        val manager = getSystemService(ConnectivityManager::class.java) ?: return
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                if (AgentState.connectedSince == 0L) reconnectNow("wifi/мобильный")
            }
        }
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        try {
            manager.registerNetworkCallback(request, callback)
            networkCallback = callback
        } catch (e: Exception) {
            log("не удалось следить за сетью: ${e.message}")
        }
    }

    private fun shutdown() {
        if (stopping && !AgentState.running) return
        stopping = true
        handler.removeCallbacks(reconnectTask)
        handler.removeCallbacks(heartbeatTask)
        networkCallback?.let {
            try {
                getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(it)
            } catch (e: Exception) {
                // уже снят — не беда
            }
        }
        networkCallback = null
        audio?.stop()
        audio = null
        caster?.stop()
        caster = null
        files?.shut()
        files = null
        hideAsk()
        socket?.close(1000, "остановлен")
        socket = null
        AgentState.running = false
        AgentState.connectedSince = 0
        setStatus("остановлен")
        log("служба остановлена")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun releaseQuietly(wake: PowerManager.WakeLock) {
        try {
            if (wake.isHeld) wake.release()
        } catch (e: Exception) {
            // отпустили дважды — не беда
        }
    }

    // ---- Мелочи -------------------------------------------------------------

    /** `https://vitazgio.ru` → `wss://vitazgio.ru/ws/agent`. */
    private fun wsUrl(server: String): String? {
        val trimmed = server.trim().trimEnd('/')
        if (trimmed.isBlank()) return null
        val base = when {
            trimmed.startsWith("https://") -> "wss://" + trimmed.removePrefix("https://")
            trimmed.startsWith("http://") -> "ws://" + trimmed.removePrefix("http://")
            trimmed.startsWith("wss://") || trimmed.startsWith("ws://") -> trimmed
            else -> "wss://$trimmed"
        }
        return "$base/ws/agent"
    }

    private fun setStatus(text: String) {
        AgentState.status = text
        val manager = getSystemService(NotificationManager::class.java)
        manager?.notify(NOTIFICATION_ID, notification(text))
    }

    private fun log(text: String) {
        AgentLog.add(this, text)
    }

    private fun createChannel() {
        val channel = NotificationChannel(
            CHANNEL,
            getString(R.string.channel_name),
            // Тихо и без звука: уведомление тут не новость, а обязательная
            // вывеска foreground-службы.
            NotificationManager.IMPORTANCE_LOW,
        )
        getSystemService(NotificationManager::class.java)?.createNotificationChannel(channel)

        val ask = NotificationChannel(
            ASK_CHANNEL,
            "Просьба показать экран",
            // Погромче вывески службы: это вопрос, на который ждут ответа,
            // и незамеченным он быть не должен.
            NotificationManager.IMPORTANCE_HIGH,
        )
        getSystemService(NotificationManager::class.java)?.createNotificationChannel(ask)
    }

    private fun notification(text: String): Notification {
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_agent)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
    }
}
