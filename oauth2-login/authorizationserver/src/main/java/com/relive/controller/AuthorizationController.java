package com.relive.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

@Controller
public class AuthorizationController {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationController.class);
    @GetMapping("/oauth2/consent")
    public String showConsentPage(
            Principal principal,
            Model model,
            @RequestParam String client_id,
            @RequestParam String scope,
            @RequestParam String state) {

        model.addAttribute("clientId", client_id);
        model.addAttribute("scopes", scope.split(" "));
        model.addAttribute("state", state);
        model.addAttribute("userName", principal.getName());
        Model currentTime = model.addAttribute("currentTime",
                LocalDateTime.now(ZoneOffset.UTC)
                        .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
        LOGGER.info("showConsentPage, client_id: {}, scope: {}, state: {}, userName: {}, currentTime: {}",
                client_id, scope, state, principal.getName(), currentTime);

        return "consent";
    }
}