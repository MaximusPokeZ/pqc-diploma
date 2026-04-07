plugins {
    id("org.springframework.boot") version "4.0.5"
    id("io.freefair.lombok") version "9.0.0"
}

description = "Demo application with load testing and observability"

dependencies {
    implementation(project(":pqc-hybrid-spring-boot-starter"))

    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("io.micrometer:micrometer-registry-prometheus")
    implementation("org.springframework.boot:spring-boot-starter-validation")

    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
}

tasks.withType<Test> {
    useJUnitPlatform()
}

springBoot {
    mainClass = "io.mzaslav.pqc.demo.PqcDemoApplication"
}
