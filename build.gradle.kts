plugins {
    id("java")
}

group = "me.clipi.ip2asn"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.jetbrains:annotations:24.0.0")
}

tasks.compileJava {
    options.release = 16
}