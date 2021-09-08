package com.manning.apisecurityinaction.controller;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.EnumSet;

public enum Permission {
    Read, Write, Delete;

    public static EnumSet<Permission> permsFromRow(ResultSet row) throws SQLException {
        return Permission.permsFrom(row.getBoolean("read"), row.getBoolean("write"), row.getBoolean("delete"));
    }

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