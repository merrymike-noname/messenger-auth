package org.kovalenko.service;

import org.kovalenko.entity.Account;
import org.kovalenko.repository.AccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Random;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AccountRepository accountRepository;
    private final TelegramService telegramService;
    private final TotpService totpService;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.otp.expiry-minutes}")
    private int otpExpiryMinutes;

    // Крок 1: надіслати OTP на Telegram
    public void sendOtp(String phoneNumber) {
        String otp = String.format("%06d", new Random().nextInt(999999));

        Account account = accountRepository.findByPhoneNumber(phoneNumber)
                .orElse(new Account());
        account.setPhoneNumber(phoneNumber);
        account.setOtpCode(otp);
        account.setOtpExpiresAt(LocalDateTime.now().plusMinutes(otpExpiryMinutes));
        account.setVerified(false);
        accountRepository.save(account);

        telegramService.sendOtp(otp);
    }

    // Крок 2: перевірити OTP
    public boolean verifyOtp(String phoneNumber, String otp) {
        return accountRepository.findByPhoneNumber(phoneNumber)
                .filter(a -> a.getOtpCode().equals(otp))
                .filter(a -> a.getOtpExpiresAt().isAfter(LocalDateTime.now()))
                .map(a -> {
                    a.setVerified(true);
                    accountRepository.save(a);
                    return true;
                })
                .orElse(false);
    }

    // Крок 3: встановити пароль та налаштувати 2FA
    public String setupPassword(String phoneNumber, String password) {
        Account account = accountRepository.findByPhoneNumber(phoneNumber)
                .orElseThrow(() -> new RuntimeException("Account not found"));

        account.setPasswordHash(passwordEncoder.encode(password));

        String totpSecret = totpService.generateSecret();
        account.setTotpSecret(totpSecret);
        accountRepository.save(account);

        return totpSecret;
    }

    // Крок 4: підтвердити 2FA і завершити реєстрацію
    public boolean confirm2fa(String phoneNumber, int totpCode) {
        Account account = accountRepository.findByPhoneNumber(phoneNumber)
                .orElseThrow(() -> new RuntimeException("Account not found"));

        boolean valid = totpService.verifyCode(account.getTotpSecret(), totpCode);
        if (valid) {
            account.set2faEnabled(true);
            accountRepository.save(account);
        }
        return valid;
    }

    public Account getAccount(String phoneNumber) {
        return accountRepository.findByPhoneNumber(phoneNumber)
                .orElseThrow(() -> new RuntimeException("Account not found"));
    }
}
