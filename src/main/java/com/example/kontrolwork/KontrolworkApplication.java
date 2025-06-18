package com.example.kontrolwork;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
@EnableAspectJAutoProxy
public class KontrolworkApplication {
    private static final Logger logger = LoggerFactory.getLogger(KontrolworkApplication.class);

    public static void main(String[] args) {
        logger.info("=== Запуск приложения Currency Tracker ===");
        logger.info("Версия Java: {}", System.getProperty("java.version"));
        logger.info("Операционная система: {} {}", System.getProperty("os.name"), System.getProperty("os.version"));
        
        try {
            SpringApplication.run(KontrolworkApplication.class, args);
            logger.info("=== Приложение Currency Tracker успешно запущено ===");
        } catch (Exception e) {
            logger.error("=== Ошибка при запуске приложения Currency Tracker: {} ===", e.getMessage(), e);
            System.exit(1);
        }
    }

}
