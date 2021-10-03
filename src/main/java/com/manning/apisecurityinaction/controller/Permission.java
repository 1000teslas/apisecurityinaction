package com.manning.apisecurityinaction.controller;

import java.util.EnumSet;

public enum Permission {
    Read, Write, Delete;

    public static EnumSet<Permission> permsFrom(boolean read, boolean write, boolean delete) {
        var perms = EnumSet.noneOf(Permission.class);
        if (read) {
            perms.add(Read);
        }
        if (write) {
            perms.add(Write);
        }
        if (delete) {
            perms.add(Delete);
        }
        return perms;
    }
}