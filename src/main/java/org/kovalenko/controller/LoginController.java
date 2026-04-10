package org.kovalenko.controller;

import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.kovalenko.service.LoginService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequiredArgsConstructor
@RequestMapping("/login")
public class LoginController {

    private final LoginService loginService;

    // Крок 1: форма введення номера і паролю
    @GetMapping
    public String loginForm() {
        return "login";
    }

    @PostMapping
    public String login(@RequestParam String phoneNumber,
                        @RequestParam String password,
                        HttpSession session, Model model) {
        if (loginService.verifyPassword(phoneNumber, password)) {
            session.setAttribute("loginPhone", phoneNumber);
            return "redirect:/login/2fa";
        }
        model.addAttribute("error", "Невірний номер телефону або пароль");
        return "login";
    }

    // Крок 2: перевірка 2FA
    @GetMapping("/2fa")
    public String login2faForm(HttpSession session) {
        if (session.getAttribute("loginPhone") == null) return "redirect:/login";
        return "login-2fa";
    }

    @PostMapping("/2fa")
    public String login2fa(@RequestParam String totpCode,
                           HttpSession session, Model model) {
        String phoneNumber = (String) session.getAttribute("loginPhone");
        if (phoneNumber == null) return "redirect:/login";

        try {
            int code = Integer.parseInt(totpCode.trim());
            if (loginService.verify2fa(phoneNumber, code)) {
                // PIN ще не встановлений — перейти до створення
                if (!loginService.hasPinSetup(phoneNumber)) {
                    return "redirect:/login/setup-pin";
                }
                // PIN потрібно запитати
                if (loginService.isPinRequired(phoneNumber)) {
                    return "redirect:/login/pin";
                }
                // PIN не потрібен — успішний логін
                session.setAttribute("authenticated", true);
                return "redirect:/login/success";
            }
        } catch (NumberFormatException ignored) {}

        model.addAttribute("error", "Невірний код. Перевірте Google Authenticator");
        return "login-2fa";
    }

    // Крок 3а: створення PIN (перший логін)
    @GetMapping("/setup-pin")
    public String setupPinForm(HttpSession session) {
        if (session.getAttribute("loginPhone") == null) return "redirect:/login";
        return "setup-pin";
    }

    @PostMapping("/setup-pin")
    public String setupPin(@RequestParam String pin,
                           @RequestParam String confirmPin,
                           HttpSession session, Model model) {
        String phoneNumber = (String) session.getAttribute("loginPhone");
        if (phoneNumber == null) return "redirect:/login";

        if (!pin.equals(confirmPin)) {
            model.addAttribute("error", "PIN-коди не співпадають");
            return "setup-pin";
        }
        if (pin.length() < 4 || pin.length() > 6) {
            model.addAttribute("error", "PIN має містити від 4 до 6 цифр");
            return "setup-pin";
        }

        loginService.setupPin(phoneNumber, pin);
        session.setAttribute("authenticated", true);
        return "redirect:/login/success";
    }

    // Крок 3б: введення існуючого PIN
    @GetMapping("/pin")
    public String pinForm(HttpSession session) {
        if (session.getAttribute("loginPhone") == null) return "redirect:/login";
        return "verify-pin";
    }

    @PostMapping("/pin")
    public String verifyPin(@RequestParam String pin,
                            HttpSession session, Model model) {
        String phoneNumber = (String) session.getAttribute("loginPhone");
        if (phoneNumber == null) return "redirect:/login";

        if (loginService.verifyPin(phoneNumber, pin)) {
            session.setAttribute("authenticated", true);
            return "redirect:/login/success";
        }

        model.addAttribute("error", "Невірний PIN-код");
        return "verify-pin";
    }

    // Успішний логін
    @GetMapping("/success")
    public String loginSuccess(HttpSession session, Model model) {
        if (session.getAttribute("authenticated") == null) return "redirect:/login";
        String phoneNumber = (String) session.getAttribute("loginPhone");
        model.addAttribute("phoneNumber", phoneNumber);
        session.removeAttribute("authenticated");
        return "login-success";
    }
}
