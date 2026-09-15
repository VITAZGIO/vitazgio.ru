package ru.vitazgio.agent

import android.webkit.JavascriptInterface

/**
 * Мост между страницей сайта и телефоном — самое опасное место всей затеи.
 *
 * Он даёт JavaScript нативные возможности, а на сайте есть страницы, где
 * показывается пришедший извне текст (ответы нейронки, имена файлов в дропе).
 * Поэтому правил три, и они не обсуждаются:
 *
 * 1. **Происхождение проверяется на КАЖДОМ вызове**, а не один раз при
 *    старте. Открылась чужая страница — мост немедленно немой. Проверяем по
 *    адресу главного кадра, который оболочка обновляет на каждом переходе
 *    (сам `WebView.getUrl()` читается только из потока интерфейса, а вызовы
 *    моста приходят из своего — ждать его отсюда значило бы рисковать
 *    взаимной блокировкой).
 * 2. **Методов мало и все узкие.** Никакого «сделай, что скажут»: команды
 *    «выполни строку» здесь нет и не будет, как и в самом протоколе агента.
 * 3. `startScreen`/`stopScreen` упираются в системное подтверждение Android:
 *    даже пробитый мост не включит трансляцию тихо — человек увидит запрос
 *    на самом телефоне и обязан нажать «Начать».
 */
class WebBridge(private val host: Host) {

    /** То немногое, что мосту нужно от оболочки. Интерфейсом, а не самой
     *  активностью: так видно, какие ровно возможности он получает. */
    interface Host {
        /** Адрес главного кадра прямо сейчас. */
        fun currentUrl(): String
        fun statusJson(): String
        fun saveAgentToken(token: String)
        fun startScreen()
        fun stopScreen()
        fun note(text: String)
    }

    companion object {
        const val NAME = "VGPhone"
        private const val ALLOWED_HOST = "vitazgio.ru"
    }

    private fun allowed(): Boolean {
        val url = host.currentUrl()
        // Только https и только свой домен (или его поддомен). Любая чужая
        // страница, открытая внутри оболочки, моста не получает.
        if (!url.startsWith("https://")) return false
        val rest = url.removePrefix("https://")
        val hostname = rest.substringBefore('/').substringBefore(':').lowercase()
        return hostname == ALLOWED_HOST || hostname.endsWith(".$ALLOWED_HOST")
    }

    /** Что оболочка знает о себе: версия, есть ли токен, жив ли агент. */
    @JavascriptInterface
    fun getStatus(): String {
        if (!allowed()) return "{}"
        return host.statusJson()
    }

    /** Показать экран телефона. Страница сайта, открытая в самой оболочке,
     *  может спросить согласие прямо здесь; с ПК та же просьба приходит
     *  телефону по сокету. И там, и там подтверждение даёт человек на
     *  телефоне — системным запросом Android, который не отключается. */
    @JavascriptInterface
    fun startScreen(): Boolean {
        if (!allowed()) return false
        host.startScreen()
        return true
    }

    @JavascriptInterface
    fun stopScreen(): Boolean {
        if (!allowed()) return false
        host.stopScreen()
        return true
    }

    /** Сайт выдал устройству личный токен — кладём его в шифрованное
     *  хранилище и поднимаем службу. */
    @JavascriptInterface
    fun saveToken(token: String): Boolean {
        if (!allowed()) return false
        val clean = token.trim()
        if (clean.isEmpty() || clean.length > 512) return false
        host.saveAgentToken(clean)
        host.note("сайт выдал токен устройству")
        return true
    }
}
