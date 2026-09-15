package ru.vitazgio.agent

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Перезагрузился телефон или обновилось само приложение — поднимаем службу,
 *  если её включали. Без этого ночной тест мог бы оборваться на обычном
 *  плановом ребуте и ничего бы не доказал. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val known = intent.action == Intent.ACTION_BOOT_COMPLETED ||
            intent.action == Intent.ACTION_MY_PACKAGE_REPLACED
        if (!known) return
        if (!AgentPrefs.enabled(context)) return
        AgentLog.add(context, "система подняла приложение (${intent.action}) — запускаю службу")
        AgentService.start(context)
    }
}
