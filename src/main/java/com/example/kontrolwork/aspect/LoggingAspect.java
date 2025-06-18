package com.example.kontrolwork.aspect;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Arrays;

@Aspect
@Component
public class LoggingAspect {
    private static final Logger logger = LoggerFactory.getLogger(LoggingAspect.class);

    /**
     * Логирование всех методов в репозиториях
     */
    @Around("execution(* com.example.kontrolwork.repository.*.*(..))")
    public Object logRepository(ProceedingJoinPoint joinPoint) throws Throwable {
        String methodName = joinPoint.getSignature().getName();
        String className = joinPoint.getTarget().getClass().getSimpleName();
        Object[] args = joinPoint.getArgs();

        logger.debug("==> Вызов метода репозитория: {}.{}() с параметрами: {}", 
                className, methodName, Arrays.toString(args));

        long startTime = System.currentTimeMillis();
        try {
            Object result = joinPoint.proceed();
            long executionTime = System.currentTimeMillis() - startTime;
            
            logger.debug("<== Метод репозитория {}.{}() выполнен за {} мс, результат: {}", 
                    className, methodName, executionTime, 
                    result != null ? result.getClass().getSimpleName() : "null");
            
            return result;
        } catch (Exception e) {
            long executionTime = System.currentTimeMillis() - startTime;
            logger.error("<!> Ошибка в методе репозитория {}.{}() за {} мс: {}", 
                    className, methodName, executionTime, e.getMessage());
            throw e;
        }
    }

    /**
     * Логирование всех методов в сервисах
     */
    @Around("execution(* com.example.kontrolwork.service.*.*(..))")
    public Object logService(ProceedingJoinPoint joinPoint) throws Throwable {
        String methodName = joinPoint.getSignature().getName();
        String className = joinPoint.getTarget().getClass().getSimpleName();
        Object[] args = joinPoint.getArgs();

        logger.debug("==> Вызов метода сервиса: {}.{}() с параметрами: {}", 
                className, methodName, Arrays.toString(args));

        long startTime = System.currentTimeMillis();
        try {
            Object result = joinPoint.proceed();
            long executionTime = System.currentTimeMillis() - startTime;
            
            logger.debug("<== Метод сервиса {}.{}() выполнен за {} мс", 
                    className, methodName, executionTime);
            
            return result;
        } catch (Exception e) {
            long executionTime = System.currentTimeMillis() - startTime;
            logger.error("<!> Ошибка в методе сервиса {}.{}() за {} мс: {}", 
                    className, methodName, executionTime, e.getMessage());
            throw e;
        }
    }

    /**
     * Логирование всех HTTP-запросов к контроллерам
     */
    @Around("execution(* com.example.kontrolwork.controller.*.*(..))")
    public Object logController(ProceedingJoinPoint joinPoint) throws Throwable {
        String methodName = joinPoint.getSignature().getName();
        String className = joinPoint.getTarget().getClass().getSimpleName();

        logger.info(">>> HTTP запрос: {}.{}()", className, methodName);

        long startTime = System.currentTimeMillis();
        try {
            Object result = joinPoint.proceed();
            long executionTime = System.currentTimeMillis() - startTime;
            
            logger.info("<<< HTTP ответ: {}.{}() выполнен за {} мс", 
                    className, methodName, executionTime);
            
            return result;
        } catch (Exception e) {
            long executionTime = System.currentTimeMillis() - startTime;
            logger.error("<<< HTTP ошибка: {}.{}() за {} мс: {}", 
                    className, methodName, executionTime, e.getMessage());
            throw e;
        }
    }

    /**
     * Логирование исключений
     */
    @AfterThrowing(pointcut = "execution(* com.example.kontrolwork..*.*(..))", throwing = "exception")
    public void logException(JoinPoint joinPoint, Throwable exception) {
        String methodName = joinPoint.getSignature().getName();
        String className = joinPoint.getTarget().getClass().getSimpleName();
        
        logger.error("Исключение в методе {}.{}(): {}", 
                className, methodName, exception.getMessage(), exception);
    }

    /**
     * Логирование выполнения планировщиков
     */
    @Around("execution(* com.example.kontrolwork.scheduler.*.*(..))")
    public Object logScheduler(ProceedingJoinPoint joinPoint) throws Throwable {
        String methodName = joinPoint.getSignature().getName();
        String className = joinPoint.getTarget().getClass().getSimpleName();

        logger.info("⏰ Запуск планировщика: {}.{}()", className, methodName);

        long startTime = System.currentTimeMillis();
        try {
            Object result = joinPoint.proceed();
            long executionTime = System.currentTimeMillis() - startTime;
            
            logger.info("⏰ Планировщик {}.{}() выполнен за {} мс", 
                    className, methodName, executionTime);
            
            return result;
        } catch (Exception e) {
            long executionTime = System.currentTimeMillis() - startTime;
            logger.error("⏰ Ошибка в планировщике {}.{}() за {} мс: {}", 
                    className, methodName, executionTime, e.getMessage());
            throw e;
        }
    }
} 