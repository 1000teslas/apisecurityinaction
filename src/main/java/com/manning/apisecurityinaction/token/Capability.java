package com.manning.apisecurityinaction.token;

import java.util.EnumSet;

import com.manning.apisecurityinaction.controller.Permission;

public record Capability(String path, EnumSet<Permission> perms) {
}
