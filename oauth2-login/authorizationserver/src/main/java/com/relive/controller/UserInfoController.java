package com.relive.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

/**
 * @author: ReLive
 * @date: 2022/6/24 4:20 下午
 */
@RestController
public class UserInfoController {
    private static final Logger LOGGER = LoggerFactory.getLogger(UserInfoController.class);

    @GetMapping("/userInfo")
    public Map<String, Object> userInfo(@AuthenticationPrincipal OAuth2User principal) {
        return principal.getAttributes();
    }

    @GetMapping("/")
    public String index() {
        return "Welcome to Authorization Server";
    }
}
