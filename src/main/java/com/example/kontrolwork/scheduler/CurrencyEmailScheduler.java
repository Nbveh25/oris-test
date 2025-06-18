package com.example.kontrolwork.scheduler;

import com.example.kontrolwork.dto.CurrencyRatesResponse;
import com.example.kontrolwork.model.User;
import com.example.kontrolwork.repository.UserRepository;
import com.example.kontrolwork.service.CurrencyService;
import com.example.kontrolwork.service.EmailService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class CurrencyEmailScheduler {
    private static final Logger logger = LoggerFactory.getLogger(CurrencyEmailScheduler.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CurrencyService currencyService;

    @Autowired
    private EmailService emailService;

    @Scheduled(cron = "${currency.email.cron}")
    public void sendDailyCurrencyRates() {
        logger.info("Начинаем отправку ежедневных курсов валют...");

        try {
            // Получаем текущие курсы валют
            CurrencyRatesResponse rates = currencyService.getCurrentRates();
            
            if (rates == null) {
                logger.error("Не удалось получить курсы валют");
                return;
            }

            // Получаем всех подписанных пользователей
            List<User> subscribedUsers = userRepository.findAllSubscribedUsers();
            logger.info("Найдено {} подписанных пользователей", subscribedUsers.size());

            // Отправляем email каждому подписанному пользователю
            for (User user : subscribedUsers) {
                try {
                    String subject = "Ежедневные курсы валют";
                    String emailContent = createPersonalizedEmailContent(user, rates);
                    
                    emailService.sendCurrencyRatesEmail(user.getEmail(), subject, emailContent);
                    
                    Thread.sleep(100); // Небольшая задержка между отправками
                } catch (Exception e) {
                    logger.error("Ошибка при отправке email пользователю {}: {}", user.getEmail(), e.getMessage());
                }
            }

            logger.info("Завершена отправка ежедневных курсов валют");
        } catch (Exception e) {
            logger.error("Ошибка в шедулере отправки курсов валют: {}", e.getMessage());
        }
    }

    private String createPersonalizedEmailContent(User user, CurrencyRatesResponse rates) {
        StringBuilder content = new StringBuilder();
        content.append("Привет, ").append(user.getFirstName()).append("!\n\n");
        content.append("Вот актуальные курсы валют на сегодня:\n\n");
        content.append(currencyService.formatRatesForEmail(rates));
        content.append("\n\nС уважением,\n");
        content.append("Команда Currency Tracker\n\n");
        content.append("Чтобы отписаться от рассылки, войдите в свой аккаунт и измените настройки.");
        
        return content.toString();
    }
}