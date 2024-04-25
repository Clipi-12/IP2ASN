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
    implementation("org.itadaki:bzip2:0.9.1")


    testCompileOnly("org.projectlombok:lombok:1.18.32")
    testAnnotationProcessor("org.projectlombok:lombok:1.18.32")

    testImplementation("org.junit.jupiter:junit-jupiter:5.7.1")
    testImplementation("org.junit.platform:junit-platform-launcher:1.10.2")
}

tasks.compileJava {
    options.release = 16
}

tasks.test {
    useJUnitPlatform()

    failFast = false

    // TODO Reduce the requirements
    maxHeapSize = "4G"

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
