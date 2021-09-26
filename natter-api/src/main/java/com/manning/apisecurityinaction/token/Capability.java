package com.manning.apisecurityinaction.token;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.checkerframework.checker.nullness.qual.Nullable;

public class Capability {
    public final @Nullable Instant expiry;
    public final Map<String, String> attributes;

    public Capability(@Nullable Instant expiry) {
        this.expiry = expiry;
        this.attributes = new ConcurrentHashMap<>();
    }
}
