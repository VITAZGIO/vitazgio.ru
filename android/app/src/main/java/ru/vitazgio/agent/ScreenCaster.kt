package ru.vitazgio.agent

import android.content.Context
import android.content.Intent
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaFormat
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.os.Bundle
import android.util.DisplayMetrics
import android.view.Surface
import android.view.WindowManager
import java.nio.ByteBuffer

/**
 * Захват экрана: MediaProjection → MediaCodec (H.264) → кадры в сокет агента.
 *
 * Три решения, которые тут важнее кода:
 *
 * 1. **Опорный кадр раз в две секунды.** Зритель, подключившийся посреди
 *    трансляции, до опорного кадра видит кашу. Две секунды — потолок этого
 *    ожидания.
 * 2. **Пауза — это `virtualDisplay.setSurface(null)`, а не остановка
 *    захвата.** Зрителей нет — кодировать в пустоту незачем (батарея и
 *    мобильный трафик), но выключить сам захват нельзя: Android 14 требует
 *    согласия человека на КАЖДУЮ сессию, и возвращение зрителя спрашивало бы
 *    его заново. Сняли поверхность — дисплею некуда рисовать, кодек молчит,
 *    сессия жива.
 * 3. **Поворот — новый кодек, а не новый виртуальный дисплей.** С Android 14
 *    `createVirtualDisplay` на одной сессии зовут ровно один раз, поэтому
 *    дисплей мы не пересоздаём, а меняем ему размер и поверхность
 *    (`resize` + `setSurface`). Новый кодек сам выдаёт свежие SPS/PPS —
 *    именно они и нужны зрителю, чтобы картинка не поехала.
 */
class ScreenCaster(
    private val context: Context,
    private val send: (ByteArray) -> Unit,
    private val state: (running: Boolean, paused: Boolean, width: Int, height: Int, error: String) -> Unit,
    private val log: (String) -> Unit,
) {

    companion object {
        private const val MIME = MediaFormat.MIMETYPE_VIDEO_AVC
        private const val LONG_SIDE_MAX = 1080
        private const val BITRATE = 3_000_000
        private const val FPS = 30
        private const val KEYFRAME_SECONDS = 2

        // Заголовок кадра: тип (1 байт) + метка времени в микросекундах
        // (8 байт, big-endian). Дальше — сам H.264 в Annex-B.
        private const val KIND_CONFIG: Byte = 1
        private const val KIND_KEY: Byte = 2
        private const val KIND_DELTA: Byte = 3
    }

    private var projection: MediaProjection? = null
    private var display: VirtualDisplay? = null
    private var codec: MediaCodec? = null
    private var input: Surface? = null
    private var pump: Thread? = null

    @Volatile
    private var running = false

    @Volatile
    private var paused = false

    @Volatile
    private var width = 0

    @Volatile
    private var height = 0

    private var rotation = -1
    private var displayListener: DisplayManager.DisplayListener? = null

    val isRunning: Boolean get() = running

    /** Та же сессия захвата, которой живёт картинка: звук берётся ею же, и
     *  отдельного согласия человека для него не требуется. */
    fun session(): MediaProjection? = projection

    /** Начать трансляцию по согласию, которое человек уже дал системе. */
    @Synchronized
    fun start(resultCode: Int, data: Intent) {
        if (running) return
        val manager = context.getSystemService(Context.MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
        val session = try {
            manager.getMediaProjection(resultCode, data)
        } catch (e: Exception) {
            fail("Система не дала захват: ${e.message}")
            return
        }
        if (session == null) {
            fail("Система не дала захват.")
            return
        }
        projection = session
        // Колбэк обязателен: с Android 14 без него createVirtualDisplay
        // бросает исключение, а нам он нужен и по делу — человек может
        // остановить трансляцию из системной шторки.
        session.registerCallback(object : MediaProjection.Callback() {
            override fun onStop() {
                log("захват остановлен системой или человеком")
                stop()
            }
        }, null)

        measure()
        try {
            openCodec()
            display = session.createVirtualDisplay(
                "vg-screen",
                width,
                height,
                densityDpi(),
                DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
                input,
                null,
                null,
            )
        } catch (e: Exception) {
            fail("Не вышло завести кодек: ${e.message}")
            stop()
            return
        }
        running = true
        paused = false
        watchRotation()
        log("трансляция пошла: ${width}×${height}")
        state(true, false, width, height, "")
    }

    @Synchronized
    fun stop() {
        if (!running && projection == null) return
        running = false
        paused = false
        unwatchRotation()
        closeCodec()
        try {
            display?.release()
        } catch (e: Exception) {
            // уже отпущен — не беда
        }
        display = null
        try {
            projection?.stop()
        } catch (e: Exception) {
            // уже остановлен — не беда
        }
        projection = null
        log("трансляция закончена")
        state(false, false, 0, 0, "")
    }

    /** Зрителей не осталось. Захват не выключаем — иначе Android спросит
     *  согласие заново, — но рисовать дисплею больше некуда. */
    @Synchronized
    fun pause() {
        if (!running || paused) return
        paused = true
        try {
            display?.surface = null
        } catch (e: Exception) {
            log("пауза не удалась: ${e.message}")
        }
        log("зрителей нет — трансляция на паузе")
        state(true, true, width, height, "")
    }

    @Synchronized
    fun resume() {
        if (!running || !paused) return
        paused = false
        try {
            display?.surface = input
        } catch (e: Exception) {
            log("возврат с паузы не удался: ${e.message}")
        }
        requestKeyFrame()
        log("зритель вернулся — продолжаю")
        state(true, false, width, height, "")
    }

    /** Новый зритель ждёт опорный кадр: с разностных картинку не собрать. */
    @Synchronized
    fun requestKeyFrame() {
        val target = codec ?: return
        try {
            target.setParameters(Bundle().apply {
                putInt(MediaCodec.PARAMETER_KEY_REQUEST_SYNC_FRAME, 0)
            })
        } catch (e: Exception) {
            // кодек уже закрыт — следующий опорный придёт по расписанию
        }
    }

    // ---- Кодек --------------------------------------------------------------

    private fun openCodec() {
        val format = MediaFormat.createVideoFormat(MIME, width, height).apply {
            setInteger(MediaFormat.KEY_COLOR_FORMAT,
                MediaCodecInfo.CodecCapabilities.COLOR_FormatSurface)
            setInteger(MediaFormat.KEY_BIT_RATE, BITRATE)
            setInteger(MediaFormat.KEY_FRAME_RATE, FPS)
            setInteger(MediaFormat.KEY_I_FRAME_INTERVAL, KEYFRAME_SECONDS)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                setInteger(MediaFormat.KEY_BITRATE_MODE,
                    MediaCodecInfo.EncoderCapabilities.BITRATE_MODE_VBR)
            }
        }
        val encoder = MediaCodec.createEncoderByType(MIME)
        encoder.configure(format, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
        input = encoder.createInputSurface()
        encoder.start()
        codec = encoder
        val worker = Thread({ drain(encoder) }, "vg-screen-encoder")
        worker.isDaemon = true
        worker.start()
        pump = worker
    }

    private fun closeCodec() {
        val encoder = codec
        codec = null
        try {
            encoder?.stop()
        } catch (e: Exception) {
            // мог не успеть стартовать — не беда
        }
        try {
            encoder?.release()
        } catch (e: Exception) {
            // уже отпущен
        }
        try {
            input?.release()
        } catch (e: Exception) {
            // уже отпущена
        }
        input = null
        pump = null
    }

    /** Кадры из кодека в сокет. Живёт своим потоком: dequeueOutputBuffer
     *  блокирующий, и держать им поток службы нельзя. */
    private fun drain(encoder: MediaCodec) {
        val info = MediaCodec.BufferInfo()
        while (true) {
            if (codec !== encoder) return
            val index = try {
                encoder.dequeueOutputBuffer(info, 250_000)
            } catch (e: Exception) {
                return
            }
            if (index < 0) continue
            val buffer: ByteBuffer? = try {
                encoder.getOutputBuffer(index)
            } catch (e: Exception) {
                return
            }
            if (buffer != null && info.size > 0) {
                buffer.position(info.offset)
                buffer.limit(info.offset + info.size)
                val kind = when {
                    info.flags and MediaCodec.BUFFER_FLAG_CODEC_CONFIG != 0 -> KIND_CONFIG
                    info.flags and MediaCodec.BUFFER_FLAG_KEY_FRAME != 0 -> KIND_KEY
                    else -> KIND_DELTA
                }
                // Разностные кадры на паузе выбрасываем, а параметры кодека
                // нет: сервер держит последние и отдаёт их новому зрителю.
                if (!paused || kind == KIND_CONFIG) {
                    val frame = ByteArray(9 + info.size)
                    frame[0] = kind
                    var stamp = info.presentationTimeUs
                    for (i in 8 downTo 1) {
                        frame[i] = (stamp and 0xff).toByte()
                        stamp = stamp shr 8
                    }
                    buffer.get(frame, 9, info.size)
                    send(frame)
                }
            }
            try {
                encoder.releaseOutputBuffer(index, false)
            } catch (e: Exception) {
                return
            }
            if (info.flags and MediaCodec.BUFFER_FLAG_END_OF_STREAM != 0) return
        }
    }

    // ---- Размер и поворот ---------------------------------------------------

    private fun measure() {
        val metrics = DisplayMetrics()
        val window = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
        @Suppress("DEPRECATION")
        window.defaultDisplay.getRealMetrics(metrics)
        var w = metrics.widthPixels
        var h = metrics.heightPixels
        val longSide = maxOf(w, h)
        if (longSide > LONG_SIDE_MAX) {
            val scale = LONG_SIDE_MAX.toDouble() / longSide
            w = (w * scale).toInt()
            h = (h * scale).toInt()
        }
        // Кодеки требуют чётных сторон, многие — кратных 16. Округляем вниз:
        // лишняя пара пикселей не стоит риска отказа кодека на старте.
        width = (w / 16) * 16
        height = (h / 16) * 16
        @Suppress("DEPRECATION")
        rotation = window.defaultDisplay.rotation
    }

    private fun densityDpi(): Int {
        val metrics = DisplayMetrics()
        val window = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
        @Suppress("DEPRECATION")
        window.defaultDisplay.getRealMetrics(metrics)
        return metrics.densityDpi
    }

    private fun watchRotation() {
        val manager = context.getSystemService(Context.DISPLAY_SERVICE) as? DisplayManager ?: return
        val listener = object : DisplayManager.DisplayListener {
            override fun onDisplayAdded(displayId: Int) {}
            override fun onDisplayRemoved(displayId: Int) {}
            override fun onDisplayChanged(displayId: Int) {
                if (displayId != android.view.Display.DEFAULT_DISPLAY) return
                val window = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
                @Suppress("DEPRECATION")
                val now = window.defaultDisplay.rotation
                if (now == rotation) return
                rebuild()
            }
        }
        manager.registerDisplayListener(listener, null)
        displayListener = listener
    }

    private fun unwatchRotation() {
        val listener = displayListener ?: return
        displayListener = null
        try {
            val manager = context.getSystemService(Context.DISPLAY_SERVICE) as? DisplayManager
            manager?.unregisterDisplayListener(listener)
        } catch (e: Exception) {
            // уже снят
        }
    }

    /** Телефон повернули: меняем кодек и подсовываем дисплею новую
     *  поверхность нужного размера. Сам дисплей НЕ пересоздаём — с
     *  Android 14 второй `createVirtualDisplay` на той же сессии запрещён,
     *  и картинка потребовала бы нового согласия человека. */
    @Synchronized
    private fun rebuild() {
        if (!running) return
        val target = display ?: return
        closeCodec()
        measure()
        try {
            openCodec()
            target.resize(width, height, densityDpi())
            target.surface = if (paused) null else input
        } catch (e: Exception) {
            fail("После поворота не вышло перезавести кодек: ${e.message}")
            stop()
            return
        }
        log("поворот: ${width}×${height}")
        state(true, paused, width, height, "")
    }

    private fun fail(text: String) {
        log(text)
        state(false, false, 0, 0, text)
    }
}
