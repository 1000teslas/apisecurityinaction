package com.manning.apisecurityinaction.token;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class Capability {
    public final Instant expiry;
    public final Map<String, String> attributes;

    public Capability(Instant expiry) {
        this.expiry = expiry;
        this.attributes = new ConcurrentHashMap<>();
    }
}
