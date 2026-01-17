import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
  alias(libs.plugins.android.application)
  kotlin("android")
  alias(libs.plugins.compose.compiler)
}

android {
  namespace = "com.appstractive.dnssd.androidapp"
  compileSdk = 36

  defaultConfig {
    minSdk = 23
    targetSdk = 36

    applicationId = "com.appstractive.dnssd.androidApp"
    versionCode = 1
    versionName = "1.0.0"
  }

  compileOptions {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
  }

  kotlin {
    compilerOptions {
      jvmTarget.set(JvmTarget.JVM_1_8)
    }
  }

  buildFeatures {
    compose = true
  }
}

dependencies {
  implementation(project(":sample:composeApp"))
  implementation(libs.androidx.appcompat)
  implementation(libs.androidx.activityCompose)
}
