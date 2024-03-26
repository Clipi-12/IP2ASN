plugins {
    id("java")
    id("eclipse")
    id("idea")
}

group = "me.clipi.ip2asn"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.jetbrains:annotations:24.0.0")

    testImplementation("org.junit.jupiter:junit-jupiter:5.7.1")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.compileJava {
    options.release = 16
}

tasks.test {
    useJUnitPlatform()

    failFast = false

    maxHeapSize = "1G"

    testLogging {
        showStandardStreams = true
        events("SKIPPED", "FAILED", "STANDARD_OUT", "STANDARD_ERROR")
    }

    project.properties["me.clipi.testing.log_level"]?.let {
        systemProperties("me.clipi.testing.log_level" to it)
    }
}

eclipse.classpath {
    isDownloadJavadoc = true
    isDownloadSources = true
}

idea.module {
    isDownloadJavadoc = true
    isDownloadSources = true
}
