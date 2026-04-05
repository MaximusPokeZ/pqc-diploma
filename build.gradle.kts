plugins {
    java
    id("io.spring.dependency-management") version "1.1.7"
}

allprojects {
    group = "io.github.mzaslav.pqc"
    version = "1.0-SNAPSHOT"

    repositories {
        mavenCentral()
    }
}

subprojects {
    apply(plugin = "java-library")
    apply(plugin = "io.spring.dependency-management")
    apply(plugin = "maven-publish")

    dependencyManagement {
        imports {
            mavenBom("org.springframework.boot:spring-boot-dependencies:4.0.5")
        }
    }

    java {
        toolchain {
            languageVersion.set(JavaLanguageVersion.of(25))
        }
    }

    dependencies {
        implementation(platform("org.junit:junit-bom:6.1.0-M1"))
        testImplementation("org.junit.jupiter:junit-jupiter")

        testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    }

    tasks.withType<Test> {
        useJUnitPlatform()
    }
}
