package com.example.kontrolwork.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
public class EmailService {
    private static final Logger logger = LoggerFactory.getLogger(EmailService.class);

    @Autowired
    private JavaMailSender mailSender;

    // Включаем отправку email
    private static final boolean EMAIL_ENABLED = true;

    public void sendCurrencyRatesEmail(String to, String subject, String content) {
        if (!EMAIL_ENABLED) {
            logger.info("Email отключен для тестирования. Сообщение для {}: {}", to, subject);
            return;
        }
        
        logger.info("Начинаем отправку email на {} с темой: {}", to, subject);
        
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom("b.f.g@internet.ru");
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(content, false);

            logger.info("Отправляем email через SMTP...");
            mailSender.send(message);
            logger.info("✅ Email с курсами валют успешно отправлен на: {}", to);
        } catch (MessagingException e) {
            logger.error("❌ Ошибка MessagingException при отправке email на {}: {}", to, e.getMessage(), e);
            throw new RuntimeException("Ошибка отправки email: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error("❌ Общая ошибка при отправке email на {}: {}", to, e.getMessage(), e);
            throw new RuntimeException("Ошибка отправки email: " + e.getMessage(), e);
        }
    }

    public void sendWelcomeEmail(String to, String firstName) {
        if (!EMAIL_ENABLED) {
            logger.info("Email отключен для тестирования. Приветственное сообщение для {}", to);
            return;
        }
        
        String subject = "Добро пожаловать в Currency Tracker!";
        String content = String.format(
                "Привет, %s!\n\n" +
                "Добро пожаловать в Currency Tracker!\n" +
                "Теперь вы будете получать ежедневные обновления курсов валют каждое утро в 9:00.\n\n" +
                "Если вы хотите отписаться от рассылки, войдите в свой аккаунт и измените настройки.\n\n" +
                "С уважением,\n" +
                "Команда Currency Tracker",
                firstName
        );

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom("b.f.g@internet.ru");
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(content, false);

            mailSender.send(message);
            logger.info("Приветственный email отправлен на: {}", to);
        } catch (MessagingException e) {
            logger.error("Ошибка при отправке приветственного email на {}: {}", to, e.getMessage());
        }
    }
} 