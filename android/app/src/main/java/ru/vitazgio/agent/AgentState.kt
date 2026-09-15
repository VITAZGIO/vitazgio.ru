package ru.vitazgio.agent

/**
 * Что показывать на экране. Отдельный объект, а не привязка службы к
 * активности: экран может быть закрыт, служба от этого не меняется, а
 * связывать их ради одной строки состояния — лишние поводы для утечек.
 */
object AgentState {

    @Volatile
    var status: String = "остановлен"

    @Volatile
    var running: Boolean = false

    @Volatile
    var connectedSince: Long = 0L

    @Volatile
    var attempts: Int = 0
}
