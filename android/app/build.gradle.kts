plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "ru.vitazgio.agent"
    compileSdk = 35

    defaultConfig {
        applicationId = "ru.vitazgio.agent"
        minSdk = 26
        targetSdk = 35
        // versionCode — это и есть «номер версии» с /api/app/version: workflow
        // кладёт его прямо в имя файла (vg-agent-<N>.apk), сайт достаёт число
        // из имени и сравнивает. Поднимать при каждой сборке, которую ставишь
        // на телефон, иначе самообновление не поймёт, что появилось новое.
        versionCode = 1
        versionName = "0.1"
    }

    buildTypes {
        debug {
            // Подпись отладочная и намеренно: приложение ставится на один
            // свой телефон, магазина в этой истории нет. Ключ генерит сам
            // Gradle, Android Studio для этого не нужна.
            isMinifyEnabled = false
        }
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        viewBinding = true
        // Номер версии приложение сообщает серверу в hello — читает его из
        // BuildConfig, а тот с AGP 8 по умолчанию не генерится.
        buildConfig = true
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    // Вебсокет: своего в Android нет, а OkHttp умеет и ping/pong на уровне
    // протокола, и переподключение отдавать нам, а не решать за нас.
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    // Токен на диске — только зашифрованным.
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
}
