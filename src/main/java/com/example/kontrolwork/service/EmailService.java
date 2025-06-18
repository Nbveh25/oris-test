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

    // Временно отключаем отправку для тестирования
    private static final boolean EMAIL_ENABLED = false;

    public void sendCurrencyRatesEmail(String to, String subject, String content) {
        if (!EMAIL_ENABLED) {
            logger.info("Email отключен для тестирования. Сообщение для {}: {}", to, subject);
            return;
        }
        
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(content, false);

            mailSender.send(message);
            logger.info("Email с курсами валют отправлен на: {}", to);
        } catch (MessagingException e) {
            logger.error("Ошибка при отправке email на {}: {}", to, e.getMessage());
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