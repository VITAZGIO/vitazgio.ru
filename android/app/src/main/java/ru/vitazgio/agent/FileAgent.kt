package ru.vitazgio.agent

import android.content.Context
import android.media.MediaScannerConnection
import android.os.Build
import android.os.Environment
import okhttp3.WebSocket
import okio.ByteString
import okio.ByteString.Companion.toByteString
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors

/**
 * Файлы телефона для страницы `/files` сайта.
 *
 * Страница там не переписана ни строкой: под ней поменялся только транспорт —
 * вместо SFTP команды приходят сюда, в тот же вебсокет, которым уже живёт
 * агент. Отсюда и набор операций: список, отдать, принять, создать папку,
 * переименовать, удалить. Команды «выполни shell» в протоколе нет и не будет.
 *
 * Разрешение — `MANAGE_EXTERNAL_STORAGE` («доступ ко всем файлам»). В отличие
 * от захвата экрана оно даётся один раз в настройках и живёт постоянно:
 * участия человека при работе не требуется, телефон может лежать в кармане.
 *
 * Файл целиком в память не тянем ни в одну сторону: с ПК летят фильмы, и
 * первый же положил бы телефон.
 */
class FileAgent(
    private val context: Context,
    private val log: (String) -> Unit,
    private val askAccess: () -> Unit = {},
) {

    companion object {
        private const val FRAME_FILE: Byte = 4
        // Сколько неотправленного терпим в сокете, прежде чем притормозить
        // чтение. Без этого телефон вычитал бы гигабайт в очередь OkHttp и
        // умер бы на памяти раньше, чем сайт успел бы его забрать.
        private const val QUEUE_LIMIT = 4L * 1024 * 1024
        private const val CHUNK_DEFAULT = 256 * 1024
    }

    private val pool = Executors.newFixedThreadPool(2)
    private val writes = ConcurrentHashMap<Int, FileOutputStream>()
    private val writePaths = ConcurrentHashMap<Int, String>()
    private val cancelled = ConcurrentHashMap<Int, Boolean>()

    /** Есть ли у нас право читать и писать файлы телефона. */
    private fun allowed(): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Environment.isExternalStorageManager()
        } else {
            true                 // до Android 11 хватает обычного разрешения
        }

    private fun home(): String = Environment.getExternalStorageDirectory().absolutePath

    /** Путь с сайта — всегда абсолютный. Наружу за пределы внешней памяти
     *  не выпускаем: «..» схлопываем и проверяем, где оказались. */
    private fun resolve(raw: String?): File? {
        val root = File(home()).canonicalFile
        val path = (raw ?: "/").ifBlank { "/" }
        val target = if (path.startsWith(root.absolutePath)) File(path) else File(root, path)
        val real = try {
            target.canonicalFile
        } catch (e: IOException) {
            return null
        }
        if (real != root && !real.path.startsWith(root.path + File.separator)) return null
        return real
    }

    fun handle(socket: WebSocket, payload: JSONObject) {
        val id = payload.optInt("id")
        val op = payload.optString("op")
        if (op == "write-end") {
            finishWrite(socket, id)
            return
        }
        if (op == "cancel") {
            cancelled[id] = true
            return
        }
        if (!allowed()) {
            // Разрешение даёт человек и только в настройках. Просить об этом
            // с сайта бесполезно — кладём уведомление, которое открывает
            // нужный экран сразу.
            askAccess()
            fail(socket, id, "Нет доступа к файлам телефона.", "denied")
            return
        }
        when (op) {
            "home" -> reply(socket, id, JSONObject().put("path", home()))
            "list" -> pool.execute { list(socket, id, payload.optString("path")) }
            "stat" -> pool.execute { stat(socket, id, payload.optString("path")) }
            "read" -> pool.execute {
                read(socket, id, payload.optString("path"),
                    payload.optInt("chunk", CHUNK_DEFAULT))
            }
            "write" -> openWrite(socket, id, payload.optString("path"))
            "mkdir" -> simple(socket, id, payload.optString("path")) { target ->
                if (target.exists()) throw Denied("Уже существует.", "exists")
                if (!target.mkdirs()) throw Denied("Не вышло создать папку.", "denied")
            }
            "rename" -> simple(socket, id, payload.optString("path")) { target ->
                val to = resolve(payload.optString("to")) ?: throw Denied("Плохой путь.", "denied")
                if (!target.renameTo(to)) throw Denied("Не вышло переименовать.", "denied")
            }
            "remove" -> simple(socket, id, payload.optString("path")) { target ->
                if (!target.exists()) throw Denied("Не найдено.", "not-found")
                if (!target.delete()) throw Denied("Не вышло удалить.", "denied")
                scan(target)
            }
            "rmdir" -> simple(socket, id, payload.optString("path")) { target ->
                if (!target.exists()) throw Denied("Не найдено.", "not-found")
                // Непустую папку с первого раза не сносим: страница на сайте
                // переспросит отдельной карточкой, и это её работа, не наша.
                if ((target.list()?.size ?: 0) > 0) throw Denied("Папка не пуста.", "not-empty")
                if (!target.delete()) throw Denied("Не вышло удалить папку.", "denied")
                scan(target)
            }
            // Неизвестную команду игнорируем молча, а не падаем — то же
            // правило, что и на той стороне.
        }
    }

    /** Кусок файла с сайта: первый байт — тип кадра, дальше номер запроса. */
    fun handleFrame(data: ByteString) {
        if (data.size < 5 || data[0] != FRAME_FILE) return
        val id = ((data[1].toInt() and 0xff) shl 24) or
            ((data[2].toInt() and 0xff) shl 16) or
            ((data[3].toInt() and 0xff) shl 8) or
            (data[4].toInt() and 0xff)
        val handle = writes[id] ?: return
        try {
            handle.write(data.toByteArray(), 5, data.size - 5)
        } catch (e: IOException) {
            log("запись оборвалась: ${e.message}")
        }
    }

    fun shut() {
        writes.values.forEach {
            try {
                it.close()
            } catch (e: IOException) {
                // уже закрыт
            }
        }
        writes.clear()
        writePaths.clear()
        cancelled.clear()
    }

    // ---- Операции -----------------------------------------------------------

    private class Denied(message: String, val code: String) : Exception(message)

    private fun list(socket: WebSocket, id: Int, path: String?) {
        val target = resolve(path)
        if (target == null || !target.isDirectory) {
            fail(socket, id, "Папка не найдена.", "not-found")
            return
        }
        val rows = JSONArray()
        for (child in target.listFiles().orEmpty()) {
            rows.put(JSONObject()
                .put("name", child.name)
                .put("dir", child.isDirectory)
                .put("size", if (child.isDirectory) 0L else child.length())
                .put("mtime", child.lastModified() / 1000))
        }
        reply(socket, id, JSONObject().put("entries", rows))
    }

    private fun stat(socket: WebSocket, id: Int, path: String?) {
        val target = resolve(path)
        if (target == null || !target.exists()) {
            fail(socket, id, "Не найдено.", "not-found")
            return
        }
        reply(socket, id, JSONObject()
            .put("dir", target.isDirectory)
            .put("size", if (target.isDirectory) 0L else target.length())
            .put("mtime", target.lastModified() / 1000))
    }

    private fun read(socket: WebSocket, id: Int, path: String?, chunk: Int) {
        val target = resolve(path)
        if (target == null || !target.isFile) {
            fail(socket, id, "Файл не найден.", "not-found")
            return
        }
        reply(socket, id, JSONObject().put("size", target.length()))
        val size = if (chunk in 4096..(1 shl 20)) chunk else CHUNK_DEFAULT
        val buffer = ByteArray(size)
        try {
            target.inputStream().use { stream ->
                while (true) {
                    if (cancelled.remove(id) == true) {
                        log("чтение отменили со стороны сайта")
                        return
                    }
                    // Не заливаем очередь сокета: сайт забирает кадры не
                    // мгновенно, а память телефона не резиновая.
                    var waited = 0
                    while (socket.queueSize() > QUEUE_LIMIT && waited < 60_000) {
                        Thread.sleep(20)
                        waited += 20
                    }
                    val read = stream.read(buffer)
                    if (read <= 0) break
                    val frame = ByteArray(5 + read)
                    frame[0] = FRAME_FILE
                    frame[1] = (id ushr 24).toByte()
                    frame[2] = (id ushr 16).toByte()
                    frame[3] = (id ushr 8).toByte()
                    frame[4] = id.toByte()
                    System.arraycopy(buffer, 0, frame, 5, read)
                    socket.send(frame.toByteString(0, frame.size))
                }
            }
            socket.send(JSONObject()
                .put("type", "fs-reply").put("id", id)
                .put("ok", true).put("eof", true).toString())
        } catch (e: Exception) {
            fail(socket, id, e.message ?: "Не вышло прочитать файл.", codeOf(e))
        } finally {
            cancelled.remove(id)
        }
    }

    private fun openWrite(socket: WebSocket, id: Int, path: String?) {
        val target = resolve(path)
        if (target == null) {
            fail(socket, id, "Плохой путь.", "denied")
            return
        }
        try {
            target.parentFile?.mkdirs()
            writes[id] = FileOutputStream(target)
            writePaths[id] = target.absolutePath
            reply(socket, id, JSONObject())
        } catch (e: Exception) {
            fail(socket, id, e.message ?: "Не вышло открыть файл на запись.", codeOf(e))
        }
    }

    private fun finishWrite(socket: WebSocket, id: Int) {
        val handle = writes.remove(id)
        val path = writePaths.remove(id)
        if (handle == null) {
            fail(socket, id, "Нечего закрывать.", "not-found")
            return
        }
        try {
            handle.flush()
            handle.close()
        } catch (e: IOException) {
            fail(socket, id, e.message ?: "Не вышло дописать файл.", codeOf(e))
            return
        }
        if (path != null) {
            // Без этого свежий фильм не появится в галерее до перезагрузки
            // телефона: медиатека не следит за файлами сама.
            scan(File(path))
            log("принят файл: ${File(path).name}")
        }
        reply(socket, id, JSONObject())
    }

    private fun simple(socket: WebSocket, id: Int, path: String?, work: (File) -> Unit) {
        pool.execute {
            val target = resolve(path)
            if (target == null) {
                fail(socket, id, "Плохой путь.", "denied")
                return@execute
            }
            try {
                work(target)
                reply(socket, id, JSONObject())
            } catch (e: Denied) {
                fail(socket, id, e.message ?: "Отказано.", e.code)
            } catch (e: Exception) {
                fail(socket, id, e.message ?: "Не вышло.", codeOf(e))
            }
        }
    }

    private fun scan(file: File) {
        try {
            MediaScannerConnection.scanFile(context, arrayOf(file.absolutePath), null, null)
        } catch (e: Exception) {
            // медиатека не отозвалась — файл от этого никуда не делся
        }
    }

    /** Внятный код вместо молчания: страница на сайте уже умеет показывать
     *  «нет места», «нет прав», «не найдено» отдельной карточкой. */
    private fun codeOf(e: Exception): String {
        val text = (e.message ?: "").lowercase()
        return when {
            e is java.io.FileNotFoundException && text.contains("permission") -> "denied"
            e is java.io.FileNotFoundException -> "not-found"
            text.contains("enospc") || text.contains("no space") -> "no-space"
            text.contains("permission") || text.contains("eacces") -> "denied"
            else -> "io"
        }
    }

    private fun reply(socket: WebSocket, id: Int, extra: JSONObject) {
        val payload = JSONObject().put("type", "fs-reply").put("id", id).put("ok", true)
        for (key in extra.keys()) payload.put(key, extra.get(key))
        socket.send(payload.toString())
    }

    private fun fail(socket: WebSocket, id: Int, text: String, code: String) {
        socket.send(JSONObject()
            .put("type", "fs-reply").put("id", id)
            .put("ok", false).put("error", text).put("code", code)
            .toString())
    }
}
