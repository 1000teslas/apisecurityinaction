package com.manning.apisecurityinaction.controller;

import java.util.EnumSet;
import java.util.Objects;
import java.util.regex.Pattern;

import org.checkerframework.checker.nullness.qual.Nullable;

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

    public static @Nullable EnumSet<Permission> permsFromString(String perms) {
        if (perms.length() > 3) {
            return null;
        }
        var p = Pattern.compile("(r?)(w?)(d?)");
        var m = p.matcher(perms);
        if (!m.matches()) {
            return null;
        }
        return permsFrom(Objects.equals(m.group(1), "r"), Objects.equals(m.group(2), "w"),
                Objects.equals(m.group(3), "d"));
    }
}