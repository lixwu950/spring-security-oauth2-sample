package com.relive.controller;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ClientCheckController {

    private final RegisteredClientRepository clientRepository;

    public ClientCheckController(RegisteredClientRepository clientRepository) {
        this.clientRepository = clientRepository;
    }

    @GetMapping("/check-client")
    public String checkClient() {
        var client = clientRepository.findByClientId("relive-client");
        return client != null ? "Client exists" : "Client NOT found";
    }
}
