package com.example.kontrolwork.controller;

import com.example.kontrolwork.dto.CurrencyRatesResponse;
import com.example.kontrolwork.service.CurrencyService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/currency")
public class CurrencyController {
    private static final Logger logger = LoggerFactory.getLogger(CurrencyController.class);

    @Autowired
    private CurrencyService currencyService;

    @GetMapping("/rates")
    public ResponseEntity<CurrencyRatesResponse> getCurrentRates() {
        logger.info("Запрос текущих курсов валют");
        
        try {
            CurrencyRatesResponse rates = currencyService.getCurrentRates();
            if (rates != null) {
                logger.info("Успешно получены курсы валют для базовой валюты: {}", rates.getBase());
                return ResponseEntity.ok(rates);
            } else {
                logger.error("Получен null при запросе курсов валют");
                return ResponseEntity.status(500).body(null);
            }
        } catch (Exception e) {
            logger.error("Ошибка при получении курсов валют: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(null);
        }
    }

    @GetMapping("/rates/formatted")
    public ResponseEntity<String> getFormattedRates() {
        logger.info("Запрос форматированных курсов валют");
        
        try {
            CurrencyRatesResponse rates = currencyService.getCurrentRates();
            if (rates != null) {
                String formattedRates = currencyService.formatRatesForEmail(rates);
                logger.info("Успешно отформатированы курсы валют. Длина ответа: {} символов", formattedRates.length());
                return ResponseEntity.ok(formattedRates);
            } else {
                logger.error("Получен null при запросе форматированных курсов валют");
                return ResponseEntity.status(500).body("Ошибка при получении курсов валют");
            }
        } catch (Exception e) {
            logger.error("Ошибка при получении форматированных курсов валют: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body("Ошибка при получении курсов валют: " + e.getMessage());
        }
    }
}