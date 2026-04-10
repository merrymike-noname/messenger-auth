package org.kovalenko.controller;

import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.kovalenko.service.AuthService;
import org.kovalenko.service.TotpService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final TotpService totpService;

    // Крок 1: введення номера телефону
    @GetMapping("/")
    public String index() {
        return "redirect:/register";
    }

    @GetMapping("/register")
    public String registerForm() {
        return "register";
    }

    @PostMapping("/register/send-otp")
    public String sendOtp(@RequestParam String phoneNumber, HttpSession session, Model model) {
        try {
            authService.sendOtp(phoneNumber);
            session.setAttribute("phoneNumber", phoneNumber);
            return "redirect:/register/verify";
        } catch (Exception e) {
            model.addAttribute("error", "Помилка відправки коду: " + e.getMessage());
            return "register";
        }
    }

    // Крок 2: введення OTP
    @GetMapping("/register/verify")
    public String verifyForm(HttpSession session, Model model) {
        model.addAttribute("phoneNumber", session.getAttribute("phoneNumber"));
        return "verify";
    }

    @PostMapping("/register/verify")
    public String verifyOtp(@RequestParam String otp, HttpSession session, Model model) {
        String phoneNumber = (String) session.getAttribute("phoneNumber");
        if (authService.verifyOtp(phoneNumber, otp)) {
            return "redirect:/register/setup-password";
        }
        model.addAttribute("error", "Невірний або прострочений код");
        model.addAttribute("phoneNumber", phoneNumber);
        return "verify";
    }

    // Крок 3: налаштування паролю
    @GetMapping("/register/setup-password")
    public String setupPasswordForm() {
        return "setup-password";
    }

    @PostMapping("/register/setup-password")
    public String setupPassword(@RequestParam String password,
                                @RequestParam String confirmPassword,
                                HttpSession session, Model model) {
        if (!password.equals(confirmPassword)) {
            model.addAttribute("error", "Паролі не співпадають");
            return "setup-password";
        }
        if (password.length() < 8) {
            model.addAttribute("error", "Пароль має містити мінімум 8 символів");
            return "setup-password";
        }

        String phoneNumber = (String) session.getAttribute("phoneNumber");
        String totpSecret = authService.setupPassword(phoneNumber, password);
        session.setAttribute("totpSecret", totpSecret);

        return "redirect:/register/setup-2fa";
    }

    // Крок 4: налаштування 2FA
    @GetMapping("/register/setup-2fa")
    public String setup2faForm(HttpSession session, Model model) {
        String phoneNumber = (String) session.getAttribute("phoneNumber");
        String totpSecret = (String) session.getAttribute("totpSecret");

        String qrCode = totpService.generateQrCodeBase64(phoneNumber, totpSecret);
        model.addAttribute("qrCode", qrCode);
        model.addAttribute("secret", totpSecret);
        return "setup-2fa";
    }

    @PostMapping("/register/setup-2fa")
    public String confirm2fa(@RequestParam String totpCode,
                             HttpSession session, Model model) {
        String phoneNumber = (String) session.getAttribute("phoneNumber");
        try {
            int code = Integer.parseInt(totpCode.trim());
            if (authService.confirm2fa(phoneNumber, code)) {
                session.invalidate();
                return "redirect:/register/success";
            }
        } catch (NumberFormatException ignored) {}

        String totpSecret = (String) session.getAttribute("totpSecret");
        String qrCode = totpService.generateQrCodeBase64(phoneNumber, totpSecret);
        model.addAttribute("qrCode", qrCode);
        model.addAttribute("secret", totpSecret);
        model.addAttribute("error", "Невірний код. Перевірте Google Authenticator");
        return "setup-2fa";
    }

    // Фінальна сторінка
    @GetMapping("/register/success")
    public String success() {
        return "success";
    }
}