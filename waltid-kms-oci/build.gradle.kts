plugins {
    id("java")
    kotlin("jvm")
}

group = "id.walt"
version = "1.0.0-SNAPSHOT"

repositories {
    mavenCentral()
}


dependencies {
    implementation("com.oracle.oci.sdk:oci-java-sdk-shaded-full:3.39.1")
    testImplementation(platform("org.junit:junit-bom:5.9.1"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    implementation(project(":waltid-crypto"))
    implementation(kotlin("stdlib-jdk8"))
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")
}

tasks.test {
    useJUnitPlatform()
}
kotlin {
    jvmToolchain(21)
}