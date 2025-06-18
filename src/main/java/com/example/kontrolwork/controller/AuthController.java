package com.example.kontrolwork.controller;

import com.example.kontrolwork.dto.LoginRequest;
import com.example.kontrolwork.dto.SignupRequest;
import com.example.kontrolwork.model.ERole;
import com.example.kontrolwork.model.Role;
import com.example.kontrolwork.model.User;
import com.example.kontrolwork.repository.RoleRepository;
import com.example.kontrolwork.repository.UserRepository;
import com.example.kontrolwork.service.EmailService;
import com.example.kontrolwork.scheduler.CurrencyEmailScheduler;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/authentication")
public class AuthController {
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    EmailService emailService;

    @Autowired
    CurrencyEmailScheduler currencyEmailScheduler;

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest, 
                                            HttpServletRequest request) {
        logger.info("=== НАЧАЛО ПРОЦЕССА ВХОДА ===");
        logger.trace("Попытка входа для пользователя: '{}'", loginRequest.getEmail());
        logger.trace("Полученные данные - Email: '{}', Password length: {}", 
                loginRequest.getEmail(), 
                loginRequest.getPassword() != null ? loginRequest.getPassword().length() : 0);
        logger.trace("Request URI: {}", request.getRequestURI());
        logger.trace("Request Method: {}", request.getMethod());
        logger.trace("Content-Type: {}", request.getContentType());
        logger.trace("User-Agent: {}", request.getHeader("User-Agent"));
        
        // Проверяем данные на null/пустоту
        if (loginRequest.getEmail() == null || loginRequest.getEmail().trim().isEmpty()) {
            logger.warn("Получен пустой email в запросе на вход");
            logger.trace("loginRequest.getEmail() = {}", loginRequest.getEmail());
            Map<String, String> error = new HashMap<>();
            error.put("error", "Email не может быть пустым");
            return ResponseEntity.badRequest().body(error);
        }
        
        if (loginRequest.getPassword() == null || loginRequest.getPassword().trim().isEmpty()) {
            logger.warn("Получен пустой пароль в запросе на вход");
            logger.trace("loginRequest.getPassword() = {}", loginRequest.getPassword() != null ? "[HIDDEN]" : "null");
            Map<String, String> error = new HashMap<>();
            error.put("error", "Пароль не может быть пустым");
            return ResponseEntity.badRequest().body(error);
        }
        
        final String cleanEmail = loginRequest.getEmail().trim();
        final String cleanPassword = loginRequest.getPassword().trim();
        
        logger.trace("Очищенные данные - Email: '{}', Password length: {}", cleanEmail, cleanPassword.length());
        
        try {
            logger.trace("Создаем объект аутентификации...");
            UsernamePasswordAuthenticationToken authToken = 
                new UsernamePasswordAuthenticationToken(cleanEmail, cleanPassword);
            logger.trace("Объект аутентификации создан: {}", authToken);
            logger.trace("Principal: {}", authToken.getPrincipal());
            logger.trace("Credentials length: {}", authToken.getCredentials() != null ? 
                authToken.getCredentials().toString().length() : 0);
            
            logger.trace("Вызываем authenticationManager.authenticate()...");
            Authentication authentication = authenticationManager.authenticate(authToken);
            logger.trace("Аутентификация завершена: {}", authentication);
            logger.trace("Authenticated: {}", authentication.isAuthenticated());
            logger.trace("Principal: {}", authentication.getPrincipal());
            logger.trace("Authorities: {}", authentication.getAuthorities());

            logger.trace("Устанавливаем контекст безопасности...");
            SecurityContextHolder.getContext().setAuthentication(authentication);
            logger.trace("Контекст безопасности установлен");
            
            // Создаем или получаем сессию и сохраняем контекст безопасности
            HttpSession session = request.getSession(true);
            logger.trace("Сессия создана/получена: {}", session.getId());
            
            // Правильное сохранение контекста безопасности в сессии
            session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, 
                                SecurityContextHolder.getContext());
            logger.trace("Контекст безопасности сохранен в сессии с правильным ключом");
            
            logger.trace("Ищем пользователя в базе данных...");
            User user = userRepository.findByEmail(cleanEmail)
                    .orElseThrow(() -> new RuntimeException("Пользователь не найден"));
            logger.trace("Пользователь найден: {}", user);
            logger.trace("User ID: {}", user.getId());
            logger.trace("User Email: {}", user.getEmail());
            logger.trace("User FirstName: {}", user.getFirstName());
            logger.trace("User LastName: {}", user.getLastName());
            logger.trace("User Roles: {}", user.getRoles());
            
            logger.info("Успешный вход пользователя: '{}'", cleanEmail);
            
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Вход выполнен успешно");
            response.put("email", user.getEmail());
            response.put("firstName", user.getFirstName());
            response.put("lastName", user.getLastName());
            
            logger.trace("Формируем ответ: {}", response);
            logger.info("=== КОНЕЦ ПРОЦЕССА ВХОДА (УСПЕХ) ===");
            return ResponseEntity.ok(response);
        } catch (BadCredentialsException e) {
            logger.warn("Неудачная попытка входа для пользователя: '{}'. Ошибка: {}", cleanEmail, e.getMessage());
            logger.trace("BadCredentialsException details: ", e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Неверный email или пароль");
            logger.info("=== КОНЕЦ ПРОЦЕССА ВХОДА (НЕВЕРНЫЕ ДАННЫЕ) ===");
            return ResponseEntity.badRequest().body(error);
        } catch (Exception e) {
            logger.error("Ошибка при входе пользователя: '{}'. Ошибка: {}", cleanEmail, e.getMessage(), e);
            logger.trace("Exception details: ", e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Внутренняя ошибка сервера");
            logger.info("=== КОНЕЦ ПРОЦЕССА ВХОДА (ОШИБКА) ===");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        logger.info("Попытка регистрации нового пользователя: {}", signUpRequest.getEmail());
        
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            logger.warn("Попытка регистрации с уже существующим email: {}", signUpRequest.getEmail());
            Map<String, String> error = new HashMap<>();
            error.put("error", "Email уже используется!");
            return ResponseEntity.badRequest().body(error);
        }

        try {
            // Создаем нового пользователя
            User user = new User(signUpRequest.getEmail(),
                    encoder.encode(signUpRequest.getPassword()),
                    signUpRequest.getFirstName(),
                    signUpRequest.getLastName());

            user.setSubscribeToRates(signUpRequest.isSubscribeToRates());
            user.setEmailVerified(true); // Для простоты считаем email подтвержденным

            Set<Role> roles = new HashSet<>();

            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Ошибка: Роль не найдена."));
            roles.add(userRole);

            user.setRoles(roles);
            userRepository.save(user);

            logger.info("Успешная регистрация пользователя: {}. Подписка на курсы: {}", 
                    signUpRequest.getEmail(), signUpRequest.isSubscribeToRates());

            // Отправляем приветственный email
            emailService.sendWelcomeEmail(user.getEmail(), user.getFirstName());

            Map<String, String> response = new HashMap<>();
            response.put("message", "Пользователь зарегистрирован успешно!");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Ошибка при регистрации пользователя {}: {}", signUpRequest.getEmail(), e.getMessage());
            Map<String, String> error = new HashMap<>();
            error.put("error", "Ошибка при регистрации пользователя");
            return ResponseEntity.badRequest().body(error);
        }
    }

    @GetMapping("/user")
    public ResponseEntity<?> getCurrentUser(HttpServletRequest request) {
        logger.info("=== ПОЛУЧЕНИЕ ИНФОРМАЦИИ О ТЕКУЩЕМ ПОЛЬЗОВАТЕЛЕ ===");
        
        try {
            // Получаем контекст безопасности из сессии
            HttpSession session = request.getSession(false);
            if (session == null) {
                logger.warn("Сессия не найдена");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Не авторизован"));
            }
            
            logger.trace("Сессия найдена: {}", session.getId());
            
            // Получаем аутентификацию из контекста безопасности
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication == null || !authentication.isAuthenticated() || 
                authentication instanceof AnonymousAuthenticationToken) {
                logger.warn("Пользователь не аутентифицирован");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Не авторизован"));
            }
            
            logger.trace("Аутентификация найдена: {}", authentication);
            logger.trace("Principal: {}", authentication.getPrincipal());
            
            String email = authentication.getName();
            logger.trace("Email из аутентификации: '{}'", email);
            
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("Пользователь не найден"));
            
            logger.trace("Пользователь найден в базе данных: {}", user.getEmail());
            
            Map<String, Object> response = new HashMap<>();
            response.put("id", user.getId());
            response.put("email", user.getEmail());
            response.put("firstName", user.getFirstName());
            response.put("lastName", user.getLastName());
            response.put("subscribeToRates", user.isSubscribeToRates());
            response.put("emailVerified", user.isEmailVerified());
            
            logger.info("Информация о пользователе '{}' успешно получена", email);
            logger.info("=== КОНЕЦ ПОЛУЧЕНИЯ ИНФОРМАЦИИ О ПОЛЬЗОВАТЕЛЕ ===");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Ошибка при получении информации о пользователе: {}", e.getMessage(), e);
            logger.info("=== КОНЕЦ ПОЛУЧЕНИЯ ИНФОРМАЦИИ О ПОЛЬЗОВАТЕЛЕ (ОШИБКА) ===");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Внутренняя ошибка сервера"));
        }
    }

    @PostMapping("/signout")
    public ResponseEntity<?> logoutUser(HttpServletRequest request) {
        logger.info("Выход пользователя из системы");
        
        try {
            // Очищаем контекст безопасности
            SecurityContextHolder.clearContext();
            
            // Инвалидируем сессию
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.invalidate();
            }
            
            Map<String, String> response = new HashMap<>();
            response.put("message", "Выход выполнен успешно");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Ошибка при выходе из системы: {}", e.getMessage());
            Map<String, String> error = new HashMap<>();
            error.put("error", "Ошибка при выходе из системы");
            return ResponseEntity.status(500).body(error);
        }
    }

    @GetMapping("/test")
    public ResponseEntity<?> testEndpoint() {
        logger.info("Тестовый эндпоинт вызван");
        Map<String, String> response = new HashMap<>();
        response.put("message", "Контроллер работает");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/test-email")
    public ResponseEntity<?> testEmailSending() {
        logger.info("Тестирование отправки email рассылки");
        
        try {
            currencyEmailScheduler.sendTestEmail();
            Map<String, String> response = new HashMap<>();
            response.put("message", "Тестовая рассылка запущена. Проверьте логи.");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Ошибка при тестировании email рассылки: {}", e.getMessage(), e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Ошибка при отправке email: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    @PostMapping("/test-smtp")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> testSmtpConnection() {
        Map<String, Object> response = new HashMap<>();
        
        try {
            // Тестируем соединение с SMTP сервером
            emailService.sendCurrencyRatesEmail("tima.bikmukhametov@inbox.ru", "Test", "Тестовое письмо для проверки соединения");
            response.put("success", true);
            response.put("message", "✅ SMTP соединение установлено успешно!");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("❌ Ошибка SMTP соединения: ", e);
            response.put("success", false);
            response.put("message", "❌ Ошибка SMTP: " + e.getMessage());
            response.put("error", e.getClass().getSimpleName());
            return ResponseEntity.status(500).body(response);
        }
    }

    @PostMapping("/test-network")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> testNetworkConnection() {
        Map<String, Object> response = new HashMap<>();
        
        try {
            // Проверяем сетевое соединение
            java.net.Socket socket = new java.net.Socket();
            socket.connect(new java.net.InetSocketAddress("smtp.internet.ru", 587), 10000);
            socket.close();
            
            response.put("success", true);
            response.put("message", "✅ Сетевое соединение с smtp.internet.ru:587 успешно!");
            return ResponseEntity.ok(response);
        } catch (java.net.SocketTimeoutException e) {
            response.put("success", false);
            response.put("message", "❌ Таймаут подключения к smtp.internet.ru:587. Возможно, порт заблокирован.");
            response.put("suggestion", "Попробуйте отключить антивирус/файрвол или обратитесь к провайдеру");
            return ResponseEntity.status(500).body(response);
        } catch (java.net.ConnectException e) {
            response.put("success", false);
            response.put("message", "❌ Невозможно подключиться к smtp.internet.ru:587. Сервер недоступен.");
            return ResponseEntity.status(500).body(response);
        } catch (Exception e) {
            logger.error("❌ Ошибка сетевого соединения: ", e);
            response.put("success", false);
            response.put("message", "❌ Сетевая ошибка: " + e.getMessage());
            return ResponseEntity.status(500).body(response);
        }
    }
}