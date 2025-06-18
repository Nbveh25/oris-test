package com.example.kontrolwork.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;

@Configuration
public class LoggingConfiguration {
    private static final Logger logger = LoggerFactory.getLogger(LoggingConfiguration.class);

    @EventListener
    public void handleContextRefresh(ContextRefreshedEvent event) {
        logger.info("=== Система логирования успешно инициализирована ===");
        logger.info("Настроены следующие уровни логирования:");
        logger.info("- Общий уровень: INFO");
        logger.info("- Приложение: DEBUG");
        logger.info("- Контроллеры: INFO");
        logger.info("- Сервисы: INFO");
        logger.info("- Безопасность: INFO");
        logger.info("- Планировщики: INFO");
        logger.info("=== Файлы логов будут сохранены в директории 'logs/' ===");
    }
} 