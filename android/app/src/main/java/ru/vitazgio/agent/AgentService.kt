package ru.vitazgio.agent

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.PowerManager
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
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

        private const val CHANNEL = "vg-agent"
        private const val NOTIFICATION_ID = 7

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
                }
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
