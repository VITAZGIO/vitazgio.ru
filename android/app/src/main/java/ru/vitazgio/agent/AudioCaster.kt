package ru.vitazgio.agent

import android.annotation.SuppressLint
import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioPlaybackCaptureConfiguration
import android.media.AudioRecord
import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaFormat
import android.media.projection.MediaProjection
import android.os.Build
import java.nio.ByteBuffer

/**
 * Звук телефона: тот же объект MediaProjection, что уже держит экран, плюс
 * AudioPlaybackCaptureConfiguration — штатный способ забрать системный звук.
 *
 * Ограничение, заданное самим Android, а не нами: захватывается звук только
 * тех приложений, которые не пометили себя как «не записывать»
 * (ALLOW_CAPTURE_BY_NONE). Ютуб и музыкальные сервисы часто так и делают —
 * их звук не придёт, и это не поломка. Звук игр, уведомлений и большинства
 * обычных приложений захватывается нормально.
 *
 * Куски звука уходят своим типом сообщений и со своей меткой времени:
 * мешать их с видеокадрами в один поток незачем, а рассинхрон потом лечится
 * сдвигом звука на стороне браузера — не перекодированием видео.
 */
class AudioCaster(
    private val send: (ByteArray) -> Unit,
    private val state: (running: Boolean, error: String) -> Unit,
    private val log: (String) -> Unit,
) {

    companion object {
        private const val MIME = MediaFormat.MIMETYPE_AUDIO_AAC
        private const val RATE = 44100
        private const val BITRATE = 96_000          // моно этого хватает с запасом
        private const val KIND_CONFIG: Byte = 5     // параметры кодека (AudioSpecificConfig)
        private const val KIND_FRAME: Byte = 6
    }

    private var record: AudioRecord? = null
    private var codec: MediaCodec? = null
    private var worker: Thread? = null

    @Volatile
    private var running = false

    val isRunning: Boolean get() = running

    @SuppressLint("MissingPermission")     // RECORD_AUDIO спрашивается до вызова
    @Synchronized
    fun start(projection: MediaProjection?) {
        if (running) return
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            fail("Захват звука есть только с Android 10.")
            return
        }
        if (projection == null) {
            // Звук берётся тем же согласием, что и картинка: без живого
            // захвата экрана его просто неоткуда взять.
            fail("Сперва включи экран — звук идёт тем же захватом.")
            return
        }
        val config = AudioPlaybackCaptureConfiguration.Builder(projection)
            .addMatchingUsage(AudioAttributes.USAGE_MEDIA)
            .addMatchingUsage(AudioAttributes.USAGE_GAME)
            .addMatchingUsage(AudioAttributes.USAGE_UNKNOWN)
            .build()
        val format = AudioFormat.Builder()
            .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
            .setSampleRate(RATE)
            .setChannelMask(AudioFormat.CHANNEL_IN_MONO)
            .build()
        val minBuffer = AudioRecord.getMinBufferSize(
            RATE, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT)
        val source = try {
            AudioRecord.Builder()
                .setAudioFormat(format)
                .setBufferSizeInBytes(maxOf(minBuffer, 8192) * 2)
                .setAudioPlaybackCaptureConfig(config)
                .build()
        } catch (e: Exception) {
            fail("Не вышло открыть звук: ${e.message}")
            return
        }

        val encoder = try {
            MediaCodec.createEncoderByType(MIME).apply {
                val out = MediaFormat.createAudioFormat(MIME, RATE, 1).apply {
                    setInteger(MediaFormat.KEY_AAC_PROFILE,
                        MediaCodecInfo.CodecProfileLevel.AACObjectLC)
                    setInteger(MediaFormat.KEY_BIT_RATE, BITRATE)
                    setInteger(MediaFormat.KEY_MAX_INPUT_SIZE, 16384)
                }
                configure(out, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
                start()
            }
        } catch (e: Exception) {
            source.release()
            fail("Не вышло завести звуковой кодек: ${e.message}")
            return
        }

        record = source
        codec = encoder
        running = true
        source.startRecording()
        val thread = Thread({ pump(source, encoder) }, "vg-audio")
        thread.isDaemon = true
        thread.start()
        worker = thread
        log("звук пошёл")
        state(true, "")
    }

    @Synchronized
    fun stop() {
        if (!running && record == null) return
        running = false
        try {
            record?.stop()
        } catch (e: Exception) {
            // уже остановлен
        }
        try {
            record?.release()
        } catch (e: Exception) {
            // уже отпущен
        }
        record = null
        val encoder = codec
        codec = null
        try {
            encoder?.stop()
        } catch (e: Exception) {
            // мог не успеть стартовать
        }
        try {
            encoder?.release()
        } catch (e: Exception) {
            // уже отпущен
        }
        worker = null
        log("звук выключен")
        state(false, "")
    }

    private fun pump(source: AudioRecord, encoder: MediaCodec) {
        val info = MediaCodec.BufferInfo()
        val buffer = ByteArray(4096)
        val started = System.nanoTime() / 1000
        while (running) {
            val read = try {
                source.read(buffer, 0, buffer.size)
            } catch (e: Exception) {
                break
            }
            if (read > 0) {
                val index = try {
                    encoder.dequeueInputBuffer(10_000)
                } catch (e: Exception) {
                    break
                }
                if (index >= 0) {
                    val input: ByteBuffer? = try {
                        encoder.getInputBuffer(index)
                    } catch (e: Exception) {
                        null
                    }
                    if (input != null) {
                        input.clear()
                        input.put(buffer, 0, read)
                        val stamp = System.nanoTime() / 1000 - started
                        try {
                            encoder.queueInputBuffer(index, 0, read, stamp, 0)
                        } catch (e: Exception) {
                            break
                        }
                    }
                }
            }
            if (!drain(encoder, info)) break
        }
    }

    private fun drain(encoder: MediaCodec, info: MediaCodec.BufferInfo): Boolean {
        while (true) {
            val index = try {
                encoder.dequeueOutputBuffer(info, 0)
            } catch (e: Exception) {
                return false
            }
            if (index < 0) return true
            val out: ByteBuffer? = try {
                encoder.getOutputBuffer(index)
            } catch (e: Exception) {
                return false
            }
            if (out != null && info.size > 0) {
                out.position(info.offset)
                out.limit(info.offset + info.size)
                val kind = if (info.flags and MediaCodec.BUFFER_FLAG_CODEC_CONFIG != 0) {
                    KIND_CONFIG
                } else {
                    KIND_FRAME
                }
                // Заголовок тот же, что у кадров экрана: тип и метка времени
                // в микросекундах. Своя метка у звука обязательна — иначе
                // рассинхрон нечем будет поправить.
                val frame = ByteArray(9 + info.size)
                frame[0] = kind
                var stamp = info.presentationTimeUs
                for (i in 8 downTo 1) {
                    frame[i] = (stamp and 0xff).toByte()
                    stamp = stamp shr 8
                }
                out.get(frame, 9, info.size)
                send(frame)
            }
            try {
                encoder.releaseOutputBuffer(index, false)
            } catch (e: Exception) {
                return false
            }
        }
    }

    private fun fail(text: String) {
        log(text)
        state(false, text)
    }
}
