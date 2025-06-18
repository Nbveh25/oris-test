package com.example.kontrolwork.config;

import com.example.kontrolwork.model.ERole;
import com.example.kontrolwork.model.Role;
import com.example.kontrolwork.repository.RoleRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements CommandLineRunner {
    private static final Logger logger = LoggerFactory.getLogger(DataInitializer.class);

    @Autowired
    private RoleRepository roleRepository;

    @Override
    public void run(String... args) throws Exception {
        logger.info("Начало инициализации данных приложения");
        
        try {
            if (roleRepository.findByName(ERole.ROLE_USER).isEmpty()) {
                roleRepository.save(new Role(ERole.ROLE_USER));
                logger.info("Создана роль ROLE_USER");
            } else {
                logger.debug("Роль ROLE_USER уже существует");
            }
            
            if (roleRepository.findByName(ERole.ROLE_ADMIN).isEmpty()) {
                roleRepository.save(new Role(ERole.ROLE_ADMIN));
                logger.info("Создана роль ROLE_ADMIN");
            } else {
                logger.debug("Роль ROLE_ADMIN уже существует");
            }
            
            logger.info("Инициализация ролей пользователей завершена успешно");
        } catch (Exception e) {
            logger.error("Ошибка при инициализации данных: {}", e.getMessage(), e);
            throw e;
        }
    }
} 