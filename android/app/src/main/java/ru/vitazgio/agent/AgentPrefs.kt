package ru.vitazgio.agent

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Адрес сайта и токен агента.
 *
 * Токен лежит только в EncryptedSharedPreferences: репозиторий публичный, и
 * телефон теряется не в теории. Запасного пути «ну сохраним открытым текстом»
 * здесь намеренно нет — если хранилище не поднялось, лучше сказать об этом
 * вслух, чем тихо положить секрет на диск как есть.
 */
object AgentPrefs {

    const val DEFAULT_SERVER = "https://vitazgio.ru"

    private const val FILE = "agent-secure"
    private const val KEY_SERVER = "server"
    private const val KEY_TOKEN = "token"
    private const val KEY_ENABLED = "enabled"

    private fun prefs(context: Context): SharedPreferences {
        val key = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        return try {
            open(context, key)
        } catch (first: Exception) {
            // Единственный известный способ починки: снести испорченный файл и
            // завести заново. Токен придётся вбить ещё раз — это честнее, чем
            // молча работать без шифрования.
            context.deleteSharedPreferences(FILE)
            open(context, key)
        }
    }

    private fun open(context: Context, key: MasterKey): SharedPreferences =
        EncryptedSharedPreferences.create(
            context,
            FILE,
            key,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )

    fun server(context: Context): String =
        prefs(context).getString(KEY_SERVER, DEFAULT_SERVER).orEmpty().ifBlank { DEFAULT_SERVER }

    fun token(context: Context): String = prefs(context).getString(KEY_TOKEN, "").orEmpty()

    fun save(context: Context, server: String, token: String) {
        prefs(context).edit()
            .putString(KEY_SERVER, server.trim())
            .putString(KEY_TOKEN, token.trim())
            .apply()
    }

    /** Должен ли агент работать. По этому флагу служба поднимается после
     *  перезагрузки телефона и после обновления самого приложения. */
    fun enabled(context: Context): Boolean = prefs(context).getBoolean(KEY_ENABLED, false)

    fun setEnabled(context: Context, value: Boolean) {
        prefs(context).edit().putBoolean(KEY_ENABLED, value).apply()
    }
}
