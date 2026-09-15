// Версии плагинов держим здесь и точными числами — по той же причине, по
// которой в requirements.txt у питоновских пакетов стоит `==`: иначе любая
// свежая мажорная версия ломает сборку без единой правки в нашем коде.
plugins {
    id("com.android.application") version "8.7.3" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
}
