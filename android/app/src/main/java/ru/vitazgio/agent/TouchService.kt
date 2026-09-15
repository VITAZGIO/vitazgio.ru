package ru.vitazgio.agent

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.graphics.Path
import android.os.Build
import android.os.Bundle
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo

/**
 * Управление пальцем с ПК: служба спец-возможностей.
 *
 * Спец-возможности — системный механизм Android, которым приложение может
 * нажимать за человека. Другого законного способа ткнуть в чужое окно у
 * приложения нет, и именно поэтому включает эту службу человек сам, руками,
 * в настройках телефона.
 *
 * Ловушка, из-за которой пункт в списке будет серым: на Android 13+ у
 * приложений, поставленных файлом (а не из магазина), спец-возможности
 * спрятаны за «разрешить ограниченные настройки» — Настройки → Приложения →
 * Vitaz Gio → три точки → разрешить. Делается один раз; это не поломка
 * приложения.
 *
 * Координаты приходят долями (0…1), а не пикселями: у ПК и телефона разные
 * разрешения, а телефон ещё и поворачивается. Переводим их в пиксели прямо
 * в момент жеста — по текущему размеру экрана, а не по запомненному.
 */
class TouchService : AccessibilityService() {

    companion object {
        /** Живая служба, если человек её включил. Агенту больше ничего о
         *  ней знать не нужно. */
        @Volatile
        var live: TouchService? = null

        private const val TAP_MS = 60L
        private const val LONG_MS = 600L
        private const val SWIPE_MS = 220L
    }

    override fun onServiceConnected() {
        super.onServiceConnected()
        live = this
        AgentLog.add(this, "управление с ПК включено")
    }

    override fun onDestroy() {
        if (live === this) live = null
        AgentLog.add(this, "управление с ПК выключено")
        super.onDestroy()
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        // Событий мы не слушаем вовсе: служба нужна только чтобы нажимать.
        // Чем меньше она видит, тем спокойнее.
    }

    override fun onInterrupt() {}

    // ---- Жесты --------------------------------------------------------------

    private fun width(): Int = resources.displayMetrics.widthPixels

    private fun height(): Int = resources.displayMetrics.heightPixels

    private fun px(fraction: Double, size: Int): Float =
        (fraction.coerceIn(0.0, 1.0) * size).toFloat()

    /** Тычок, долгое нажатие или свайп — всё это один путь с разной
     *  длительностью, поэтому и собирается одинаково. */
    fun gesture(kind: String, x: Double, y: Double, x2: Double, y2: Double, ms: Long): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) return false
        val path = Path()
        val startX = px(x, width())
        val startY = px(y, height())
        path.moveTo(startX, startY)
        val duration = when (kind) {
            "long" -> if (ms > 0) ms else LONG_MS
            "swipe" -> if (ms > 0) ms else SWIPE_MS
            else -> if (ms > 0) ms else TAP_MS
        }.coerceIn(20L, 10_000L)
        if (kind == "swipe") path.lineTo(px(x2, width()), px(y2, height()))
        val stroke = GestureDescription.StrokeDescription(path, 0, duration)
        return try {
            dispatchGesture(GestureDescription.Builder().addStroke(stroke).build(), null, null)
        } catch (e: Exception) {
            AgentLog.add(this, "жест не прошёл: ${e.message}")
            false
        }
    }

    /** «Назад», «Домой», «Недавние» — это не жесты, а системные действия:
     *  тыкать в их места на экране было бы гаданием. */
    fun key(name: String): Boolean {
        val action = when (name) {
            "back" -> GLOBAL_ACTION_BACK
            "home" -> GLOBAL_ACTION_HOME
            "recents" -> GLOBAL_ACTION_RECENTS
            "notifications" -> GLOBAL_ACTION_NOTIFICATIONS
            else -> return false
        }
        return performGlobalAction(action)
    }

    /** Текст с клавиатуры ПК. Уходит в то поле, которое сейчас в фокусе на
     *  телефоне; фокуса нет — врать «получилось» не будем. */
    fun type(text: String): Boolean {
        val focused = findFocus(AccessibilityNodeInfo.FOCUS_INPUT) ?: return false
        return try {
            val current = focused.text?.toString().orEmpty()
            val arguments = Bundle().apply {
                putCharSequence(
                    AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE,
                    current + text,
                )
            }
            focused.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, arguments)
        } catch (e: Exception) {
            false
        } finally {
            focused.recycle()
        }
    }

    /** Backspace: стираем последний символ того же поля. */
    fun backspace(): Boolean {
        val focused = findFocus(AccessibilityNodeInfo.FOCUS_INPUT) ?: return false
        return try {
            val current = focused.text?.toString().orEmpty()
            if (current.isEmpty()) return false
            val arguments = Bundle().apply {
                putCharSequence(
                    AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE,
                    current.dropLast(1),
                )
            }
            focused.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, arguments)
        } catch (e: Exception) {
            false
        } finally {
            focused.recycle()
        }
    }
}
