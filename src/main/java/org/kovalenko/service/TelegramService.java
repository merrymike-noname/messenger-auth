package org.kovalenko.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

@Service
public class TelegramService {

    @Value("${telegram.bot.token}")
    private String botToken;

    @Value("${telegram.bot.chat-id}")
    private String chatId;

    private final WebClient webClient = WebClient.create("https://api.telegram.org");

    public void sendOtp(String otp) {
        String message = "🔐 Ваш код підтвердження: *" + otp + "*\n\nКод дійсний 5 хвилин.";
        String url = "/bot" + botToken + "/sendMessage";

        webClient.post()
                .uri(url)
                .bodyValue(new TelegramMessage(chatId, message, "Markdown"))
                .retrieve()
                .bodyToMono(String.class)
                .subscribe();
    }

    record TelegramMessage(String chat_id, String text, String parse_mode) {}
}
