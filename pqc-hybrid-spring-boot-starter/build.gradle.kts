plugins {
	`java-library`
}

description = "Starter that pulls everything together"

dependencies {
    api(project(":pqc-spring-boot-autoconfigure"))

    implementation("org.springframework.boot:spring-boot-starter")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
}