package org.kovalenko.service;

import lombok.RequiredArgsConstructor;
import org.kovalenko.entity.Account;
import org.kovalenko.repository.AccountRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class LoginService {

    private final AccountRepository accountRepository;
    private final TotpService totpService;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.pin.interval-minutes}")
    private int pinIntervalMinutes;

    // Крок 1: перевірити номер телефону і пароль
    public boolean verifyPassword(String phoneNumber, String password) {
        return accountRepository.findByPhoneNumber(phoneNumber)
                .filter(Account::is2faEnabled)
                .map(a -> passwordEncoder.matches(password, a.getPasswordHash()))
                .orElse(false);
    }

    // Крок 2: перевірити 2FA код
    public boolean verify2fa(String phoneNumber, int totpCode) {
        return accountRepository.findByPhoneNumber(phoneNumber)
                .map(a -> totpService.verifyCode(a.getTotpSecret(), totpCode))
                .orElse(false);
    }

    // Крок 3: перевірити чи потрібно запитувати PIN
    public boolean isPinRequired(String phoneNumber) {
        return accountRepository.findByPhoneNumber(phoneNumber)
                .map(a -> {
                    // PIN ще не встановлений
                    if (a.getPinHash() == null) return false;
                    // PIN ніколи не запитувався або минув інтервал
                    if (a.getPinLastAskedAt() == null) return true;
                    return a.getPinLastAskedAt()
                            .plusMinutes(pinIntervalMinutes)
                            .isBefore(LocalDateTime.now());
                })
                .orElse(false);
    }

    // Крок 3: перевірити введений PIN
    public boolean verifyPin(String phoneNumber, String pin) {
        return accountRepository.findByPhoneNumber(phoneNumber)
                .filter(a -> a.getPinHash() != null)
                .map(a -> {
                    boolean valid = passwordEncoder.matches(pin, a.getPinHash());
                    if (valid) {
                        a.setPinLastAskedAt(LocalDateTime.now());
                        accountRepository.save(a);
                    }
                    return valid;
                })
                .orElse(false);
    }

    // Крок 3: встановити PIN (перший логін після реєстрації)
    public void setupPin(String phoneNumber, String pin) {
        Account account = accountRepository.findByPhoneNumber(phoneNumber)
                .orElseThrow(() -> new RuntimeException("Account not found"));
        account.setPinHash(passwordEncoder.encode(pin));
        account.setPinLastAskedAt(LocalDateTime.now());
        accountRepository.save(account);
    }

    // Перевірити чи PIN вже встановлений
    public boolean hasPinSetup(String phoneNumber) {
        return accountRepository.findByPhoneNumber(phoneNumber)
                .map(a -> a.getPinHash() != null)
                .orElse(false);
    }
}
