package com.example.kontrolwork.service;

import com.example.kontrolwork.dto.CurrencyRatesResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

@Service
public class CurrencyService {
    private static final Logger logger = LoggerFactory.getLogger(CurrencyService.class);

    @Value("${currency.api.url}")
    private String apiUrl;

    private final WebClient webClient;

    public CurrencyService() {
        this.webClient = WebClient.builder().build();
        logger.info("CurrencyService инициализирован");
    }

    public CurrencyRatesResponse getCurrentRates() {
        logger.info("Запрос курсов валют с API: {}", apiUrl);
        
        try {
            Mono<CurrencyRatesResponse> response = webClient.get()
                    .uri(apiUrl)
                    .retrieve()
                    .bodyToMono(CurrencyRatesResponse.class);

            CurrencyRatesResponse result = response.block();
            
            if (result != null) {
                logger.info("Успешно получены курсы валют. Базовая валюта: {}, Количество курсов: {}", 
                        result.getBase(), result.getRates() != null ? result.getRates().size() : 0);
            } else {
                logger.warn("API вернул null, используем мок-данные");
            }
            
            return result;
        } catch (Exception e) {
            logger.error("Ошибка при получении курсов валют с API {}: {}. Используем мок-данные", apiUrl, e.getMessage());
            // Возвращаем мок-данные в случае ошибки
            return createMockRates();
        }
    }

    private CurrencyRatesResponse createMockRates() {
        logger.info("Создание мок-данных для курсов валют");
        
        CurrencyRatesResponse mockResponse = new CurrencyRatesResponse();
        mockResponse.setBase("USD");
        mockResponse.setDate("2024-01-01");
        
        Map<String, Double> rates = Map.of(
                "EUR", 0.85,
                "GBP", 0.73,
                "RUB", 75.0,
                "JPY", 110.0,
                "CNY", 6.45
        );
        
        mockResponse.setRates(rates);
        logger.debug("Созданы мок-данные с {} валютами", rates.size());
        
        return mockResponse;
    }

    public String formatRatesForEmail(CurrencyRatesResponse rates) {
        logger.debug("Форматирование курсов валют для email");
        
        if (rates == null) {
            logger.warn("Попытка форматирования null курсов валют");
            return "Курсы валют недоступны";
        }
        
        StringBuilder sb = new StringBuilder();
        sb.append("Курсы валют на ").append(rates.getDate()).append("\n\n");
        sb.append("Базовая валюта: ").append(rates.getBase()).append("\n\n");
        
        if (rates.getRates() != null) {
            rates.getRates().forEach((currency, rate) -> {
                sb.append(String.format("%s: %.4f\n", currency, rate));
            });
            logger.debug("Отформатированы курсы для {} валют", rates.getRates().size());
        } else {
            logger.warn("Курсы валют отсутствуют в ответе");
            sb.append("Данные о курсах валют недоступны\n");
        }
        
        return sb.toString();
    }
} 