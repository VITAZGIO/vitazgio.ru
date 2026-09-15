package ru.vitazgio.agent

import android.content.Context
import android.util.Log
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Журнал на диске, а не в памяти.
 *
 * Весь смысл первой ступени — узнать, доживёт ли соединение до утра. Если
 * оболочка убьёт процесс, память уйдёт вместе с ним, и утром смотреть будет
 * не на что. Поэтому каждая строчка сразу дописывается в файл, а экран
 * показывает его хвост.
 */
object AgentLog {

    private const val FILE = "agent-log.txt"
    private const val MAX_BYTES = 256 * 1024
    private const val KEEP_BYTES = 128 * 1024

    private val stamp = SimpleDateFormat("dd.MM HH:mm:ss", Locale.getDefault())
    private val lock = Any()

    fun file(context: Context): File = File(context.filesDir, FILE)

    fun add(context: Context, text: String) {
        val line = "${stamp.format(Date())}  $text\n"
        Log.i("VgAgent", text)
        synchronized(lock) {
            try {
                val file = file(context)
                file.appendText(line)
                if (file.length() > MAX_BYTES) {
                    val tail = file.readText().takeLast(KEEP_BYTES)
                    file.writeText(tail.substringAfter('\n', tail))
                }
            } catch (e: Exception) {
                Log.w("VgAgent", "журнал не пишется: ${e.message}")
            }
        }
    }

    fun tail(context: Context, lines: Int = 400): String = synchronized(lock) {
        try {
            val file = file(context)
            if (!file.exists()) return ""
            file.readLines().takeLast(lines).joinToString("\n")
        } catch (e: Exception) {
            "журнал не читается: ${e.message}"
        }
    }
}
