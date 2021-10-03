package com.manning.apisecurityinaction.token;

import java.time.Instant;
import java.util.EnumSet;

import com.manning.apisecurityinaction.controller.Permission;

import org.checkerframework.checker.nullness.qual.Nullable;

public record Capability(@Nullable Instant expiry, String path, EnumSet<Permission> perms) {
}
