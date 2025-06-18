package com.example.kontrolwork.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class WebController {
    private static final Logger logger = LoggerFactory.getLogger(WebController.class);

    @GetMapping("/")
    public String home() {
        logger.debug("Переход на главную страницу");
        return "index";
    }

    @GetMapping("/home")
    public String homePage() {
        logger.debug("Переход на домашнюю страницу");
        return "index";
    }

    @GetMapping("/register")
    public String register() {
        logger.debug("Переход на страницу регистрации");
        return "register";
    }

    @GetMapping("/login")
    public String login() {
        logger.debug("Переход на страницу входа");
        return "login";
    }

    @GetMapping("/dashboard")
    public String dashboard() {
        logger.debug("Переход на страницу дашборда");
        
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || 
            authentication instanceof AnonymousAuthenticationToken) {
            logger.debug("Пользователь не аутентифицирован, перенаправляем на логин");
            return "redirect:/login";
        }
        
        logger.debug("Пользователь аутентифицирован: {}", authentication.getName());
        return "dashboard";
    }
} 