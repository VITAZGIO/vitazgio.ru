package ru.vitazgio.agent

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import ru.vitazgio.agent.databinding.ActivityAgentBinding

/**
 * Служебный экран: адрес, токен руками, состояние и журнал.
 *
 * С ТЗ 2 он больше не главный — главным стала оболочка с сайтом
 * (`MainActivity`), а токен приезжает с сайта сам. Живые показания и кнопки
 * (статус, версии, токены устройства) переехали на сам сайт — кабинет →
 * вкладка «Приложения» (`/apps`), их видно и с ПК, и с телефона. Этот экран
 * остаётся запасным путём на случай, когда сайт недоступен: местный журнал
 * без него было бы негде посмотреть. Открывается кнопкой «Журнал» на
 * уведомлении службы, не долгим тычком по полоске — той на сайте больше нет.
 */
class AgentActivity : AppCompatActivity() {

    private lateinit var views: ActivityAgentBinding
    private val ui = Handler(Looper.getMainLooper())

    private val refresh = object : Runnable {
        override fun run() {
            views.status.text = statusLine()
            val log = AgentLog.tail(this@AgentActivity)
            if (views.log.text.toString() != log) {
                views.log.text = log
                views.logScroll.post { views.logScroll.fullScroll(android.view.View.FOCUS_DOWN) }
            }
            ui.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        views = ActivityAgentBinding.inflate(layoutInflater)
        setContentView(views.root)

        views.server.setText(AgentPrefs.server(this))
        views.token.setText(AgentPrefs.token(this))

        views.start.setOnClickListener {
            val server = views.server.text.toString().trim()
            val token = views.token.text.toString().trim()
            if (token.isBlank()) {
                Toast.makeText(this, "Без токена сервер не пустит", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            AgentPrefs.save(this, server.ifBlank { AgentPrefs.DEFAULT_SERVER }, token)
            AgentPrefs.setEnabled(this, true)
            askNotifications()
            AgentService.start(this)
        }

        views.stop.setOnClickListener {
            AgentPrefs.setEnabled(this, false)
            AgentService.stop(this)
        }

        views.copyLog.setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboard.setPrimaryClip(ClipData.newPlainText("vg-agent", AgentLog.tail(this, 2000)))
            Toast.makeText(this, "Журнал скопирован", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onResume() {
        super.onResume()
        ui.post(refresh)
    }

    override fun onPause() {
        ui.removeCallbacks(refresh)
        super.onPause()
    }

    private fun statusLine(): String {
        val since = AgentState.connectedSince
        if (since > 0) {
            val minutes = (System.currentTimeMillis() - since) / 60000
            return "${AgentState.status} · $minutes мин"
        }
        return AgentState.status
    }

    /** Без разрешения уведомление foreground-службы не покажется, а без него
     *  оболочка гасит её тем охотнее. */
    private fun askNotifications() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val granted = ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
        if (granted != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }
    }
}
