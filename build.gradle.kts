plugins {
    java
    id("org.springframework.boot") version "3.5.0"
    id("io.spring.dependency-management") version "1.1.7"
}

group = "ru.kpfu.itis.ahmed"
version = "0.0.1-SNAPSHOT"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-mail")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-thymeleaf")
    implementation("org.thymeleaf.extras:thymeleaf-extras-springsecurity6")
    
    // AOP для логирования
    implementation("org.springframework.boot:spring-boot-starter-aop")
    
    // База данных H2 (основная для разработки)
    runtimeOnly("com.h2database:h2")
    
    // База данных PostgreSQL (дополнительная для продакшена)
    runtimeOnly("org.postgresql:postgresql")
    
    // JSON обработка
    implementation("com.fasterxml.jackson.core:jackson-databind")
    
    // HTTP клиент для работы с внешними API
    implementation("org.springframework.boot:spring-boot-starter-webflux")
    
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<Test> {
    useJUnitPlatform()
}
