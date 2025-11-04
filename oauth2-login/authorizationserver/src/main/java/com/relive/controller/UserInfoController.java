package com.relive.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
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

    @PostMapping("userInfo")
    public Map<String, Object> getUserInfo(@AuthenticationPrincipal Jwt jwt) {
        LOGGER.info("getUserInfo, jwt: {}", jwt);
        return Collections.singletonMap("data", jwt.getClaims());
    }
}
