package org.kovalenko.controller;

import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.kovalenko.service.AuthService;
import org.kovalenko.service.LoginService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequiredArgsConstructor
@RequestMapping("/recovery")
public class RecoveryController {

    private final AuthService authService;
    private final LoginService loginService;

    // Крок 1: введення номера телефону
    @GetMapping
    public String recoveryForm() {
        return "recovery";
    }

    @PostMapping
    public String sendOtp(@RequestParam String phoneNumber,
                          HttpSession session, Model model) {
        try {
            authService.sendOtpForRecovery(phoneNumber);
            session.setAttribute("recoveryPhone", phoneNumber);
            return "redirect:/recovery/verify";
        } catch (RuntimeException e) {
            model.addAttribute("error", "Акаунт з таким номером не знайдено");
            return "recovery";
        }
    }

    // Крок 2: підтвердження OTP
    @GetMapping("/verify")
    public String verifyForm(HttpSession session, Model model) {
        if (session.getAttribute("recoveryPhone") == null) return "redirect:/recovery";
        model.addAttribute("phoneNumber", session.getAttribute("recoveryPhone"));
        return "recovery-verify";
    }

    @PostMapping("/verify")
    public String verifyOtp(@RequestParam String otp,
                            HttpSession session, Model model) {
        String phoneNumber = (String) session.getAttribute("recoveryPhone");
        if (phoneNumber == null) return "redirect:/recovery";

        if (authService.verifyOtp(phoneNumber, otp)) {
            return "redirect:/recovery/verify-pin";
        }

        model.addAttribute("error", "Невірний або прострочений код");
        model.addAttribute("phoneNumber", phoneNumber);
        return "recovery-verify";
    }

    // Крок 3: підтвердження PIN
    @GetMapping("/verify-pin")
    public String verifyPinForm(HttpSession session) {
        if (session.getAttribute("recoveryPhone") == null) return "redirect:/recovery";
        return "recovery-verify-pin";
    }

    @PostMapping("/verify-pin")
    public String verifyPin(@RequestParam String pin,
                            HttpSession session, Model model) {
        String phoneNumber = (String) session.getAttribute("recoveryPhone");
        if (phoneNumber == null) return "redirect:/recovery";

        if (loginService.verifyPin(phoneNumber, pin)) {
            return "redirect:/recovery/new-password";
        }

        model.addAttribute("error", "Невірний PIN-код");
        return "recovery-verify-pin";
    }

    // Крок 4: введення нового паролю
    @GetMapping("/new-password")
    public String newPasswordForm(HttpSession session) {
        if (session.getAttribute("recoveryPhone") == null) return "redirect:/recovery";
        return "recovery-new-password";
    }

    @PostMapping("/new-password")
    public String resetPassword(@RequestParam String password,
                                @RequestParam String confirmPassword,
                                HttpSession session, Model model) {
        String phoneNumber = (String) session.getAttribute("recoveryPhone");
        if (phoneNumber == null) return "redirect:/recovery";

        if (!password.equals(confirmPassword)) {
            model.addAttribute("error", "Паролі не співпадають");
            return "recovery-new-password";
        }
        if (password.length() < 8) {
            model.addAttribute("error", "Пароль має містити мінімум 8 символів");
            return "recovery-new-password";
        }

        authService.resetPassword(phoneNumber, password);
        session.removeAttribute("recoveryPhone");
        return "redirect:/recovery/success";
    }

    @GetMapping("/success")
    public String recoverySuccess() {
        return "recovery-success";
    }
}