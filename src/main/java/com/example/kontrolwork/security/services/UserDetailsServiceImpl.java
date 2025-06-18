package com.example.kontrolwork.security.services;

import com.example.kontrolwork.model.Role;
import com.example.kontrolwork.model.User;
import com.example.kontrolwork.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    private static final Logger logger = LoggerFactory.getLogger(UserDetailsServiceImpl.class);
    
    @Autowired
    UserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        logger.info("=== НАЧАЛО ЗАГРУЗКИ ПОЛЬЗОВАТЕЛЯ ===");
        logger.trace("Попытка загрузки пользователя по username: '{}'", username);
        logger.trace("username type: {}", username != null ? username.getClass().getSimpleName() : "null");
        logger.trace("username length: {}", username != null ? username.length() : 0);
        
        // Дополнительная проверка на пустой email
        if (username == null) {
            logger.warn("Передан null username для аутентификации");
            logger.trace("username = null");
            throw new UsernameNotFoundException("Username не может быть null");
        }
        
        if (username.trim().isEmpty()) {
            logger.warn("Передан пустой username для аутентификации");
            logger.trace("username = '{}'", username);
            logger.trace("username.trim() = '{}'", username.trim());
            throw new UsernameNotFoundException("Username не может быть пустым");
        }
        
        final String cleanEmail = username.trim();
        logger.trace("Username после обработки: '{}'", cleanEmail);
        logger.trace("cleanEmail length: {}", cleanEmail.length());
        
        logger.trace("Вызываем userRepository.findByEmail('{}')...", cleanEmail);
        Optional<User> userOptional = userRepository.findByEmail(cleanEmail);
        logger.trace("Результат поиска: {}", userOptional.isPresent() ? "найден" : "не найден");
        
        User user = userOptional.orElseThrow(() -> {
            logger.warn("Пользователь не найден: '{}'", cleanEmail);
            logger.trace("userOptional.isPresent() = {}", userOptional.isPresent());
            return new UsernameNotFoundException("Пользователь не найден: " + cleanEmail);
        });

        logger.trace("Пользователь найден в базе данных:");
        logger.trace("  User ID: {}", user.getId());
        logger.trace("  User Email: '{}'", user.getEmail());
        logger.trace("  User FirstName: '{}'", user.getFirstName());
        logger.trace("  User LastName: '{}'", user.getLastName());
        logger.trace("  User Password: [HIDDEN - length: {}]", user.getPassword() != null ? user.getPassword().length() : 0);
        logger.trace("  User EmailVerified: {}", user.isEmailVerified());
        logger.trace("  User SubscribeToRates: {}", user.isSubscribeToRates());
        logger.trace("  User CreatedAt: {}", user.getCreatedAt());
        
        logger.trace("Загружаем роли пользователя...");
        Set<Role> roles = user.getRoles();
        logger.trace("Количество ролей: {}", roles != null ? roles.size() : 0);
        
        if (roles != null) {
            for (Role role : roles) {
                logger.trace("  Роль: ID={}, Name={}", role.getId(), role.getName());
            }
        }

        logger.trace("Преобразуем роли в GrantedAuthority...");
        List<GrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> {
                    String roleName = role.getName().name();
                    logger.trace("    Преобразуем роль: {} -> {}", role.getName(), roleName);
                    return new SimpleGrantedAuthority(roleName);
                })
                .collect(Collectors.toList());

        logger.trace("Список authorities:");
        for (GrantedAuthority authority : authorities) {
            logger.trace("  Authority: {}", authority.getAuthority());
        }

        logger.trace("Создаем объект UserDetails...");
        UserDetails userDetails = org.springframework.security.core.userdetails.User.builder()
                .username(user.getEmail())
                .password(user.getPassword())
                .authorities(authorities)
                .build();
        
        logger.trace("UserDetails создан:");
        logger.trace("  Username: '{}'", userDetails.getUsername());
        logger.trace("  Password: [HIDDEN - length: {}]", userDetails.getPassword() != null ? userDetails.getPassword().length() : 0);
        logger.trace("  Authorities: {}", userDetails.getAuthorities());
        logger.trace("  AccountNonExpired: {}", userDetails.isAccountNonExpired());
        logger.trace("  AccountNonLocked: {}", userDetails.isAccountNonLocked());
        logger.trace("  CredentialsNonExpired: {}", userDetails.isCredentialsNonExpired());
        logger.trace("  Enabled: {}", userDetails.isEnabled());

        logger.info("Пользователь '{}' успешно загружен с ролями: {}", cleanEmail, 
                authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()));
        logger.info("=== КОНЕЦ ЗАГРУЗКИ ПОЛЬЗОВАТЕЛЯ ===");

        return userDetails;
    }
} 