package ru.vitazgio.agent

import android.app.Application
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter

/**
 * Приложение целиком. Нужно ради одной вещи: падение не должно исчезать
 * бесследно.
 *
 * Телефон далеко, консоли под рукой нет, и «просто вылетает» — это диагноз,
 * с которым нечего делать. Поэтому последний вздох записывается в журнал и в
 * отдельный файл, а оболочка при следующем запуске показывает его карточкой
 * с кнопкой «скопировать»: остаётся прислать текст, а не пересказывать.
 */
class VgApp : Application() {

    companion object {
        private const val CRASH_FILE = "last-crash.txt"

        fun crashFile(context: android.content.Context): File =
            File(context.filesDir, CRASH_FILE)

        /** Текст последнего падения, если оно было. */
        fun lastCrash(context: android.content.Context): String? {
            val file = crashFile(context)
            if (!file.exists()) return null
            return try {
                file.readText().ifBlank { null }
            } catch (e: Exception) {
                null
            }
        }

        fun forgetCrash(context: android.content.Context) {
            try {
                crashFile(context).delete()
            } catch (e: Exception) {
                // не удалилось — покажем ещё раз, не беда
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, error ->
            try {
                val trace = StringWriter()
                error.printStackTrace(PrintWriter(trace))
                val text = "поток ${thread.name}: ${error}\n$trace"
                AgentLog.add(this, "ПАДЕНИЕ: ${error}")
                crashFile(this).writeText(text.take(8000))
            } catch (e: Throwable) {
                // записать не вышло — хотя бы не мешаем системе дописать своё
            }
            // Отдаём падение системе дальше: глотать его молча нельзя, иначе
            // приложение останется в нерабочем состоянии вместо перезапуска.
            previous?.uncaughtException(thread, error)
        }
    }
}
