package com.manning.apisecurityinaction.token;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class AuthnToken {
    public final Instant expiry;
    public final String username;
    public final Map<String, String> attributes;

    public AuthnToken(Instant expiry, String username) {
        this.expiry = expiry;
        this.username = username;
        this.attributes = new ConcurrentHashMap<>();
    }
}
