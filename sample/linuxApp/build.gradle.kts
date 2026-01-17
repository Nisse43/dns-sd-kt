plugins {
    alias(libs.plugins.multiplatform)
}

kotlin {
    linuxX64 {
        binaries {
            executable {
                entryPoint = "main"
            }
        }
    }
    linuxArm64 {
        binaries {
            executable {
                entryPoint = "main"
            }
        }
    }

    sourceSets {
        nativeMain.dependencies {
            implementation(project(":dns-sd-kt"))
            implementation(libs.kotlin.coroutines)
            implementation(libs.ktor.network)
        }
    }
}
