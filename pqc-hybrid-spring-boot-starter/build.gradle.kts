plugins {
    `java-library`
}

description = "Starter that pulls everything together for Hybrid PQC Cryptography"

dependencies {
    api(project(":pqc-crypto-core"))

    api(project(":pqc-spring-boot-autoconfigure"))

    api("org.springframework.boot:spring-boot-starter")
}
