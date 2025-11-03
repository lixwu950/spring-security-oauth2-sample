package com.relive.controller;

import java.security.Principal;
import org.springframework.security.oauth2.jwt.Jwt;

public class JwtPrincipal implements Principal {
    private final Jwt jwt;

    public JwtPrincipal(Jwt jwt) {
        this.jwt = jwt;
    }

    @Override
    public String getName() {
        return jwt.getSubject(); // 通常是 sub 字段
    }

    public Jwt getJwt() {
        return jwt;
    }
}
