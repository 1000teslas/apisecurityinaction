package com.manning.apisecurityinaction.token;

import java.security.SecureRandom;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;

import com.manning.apisecurityinaction.controller.Permission;

import org.dalesbred.Database;

import spark.Request;

import static org.checkerframework.checker.nullness.util.NullnessUtil.castNonNull;

public record CapabilityStore(Database database, SecureRandom rng) implements ConfidentialTokenStore<Capability> {
    @Override
    public String create(Request request, Capability token) {
        var tokenId = randomId();

        database.updateUnique("INSERT INTO caps(cap_id, path, r, w, d) VALUES(?, ?, ?, ?, ?);", Util.hash(tokenId),
                token.path(), token.perms().contains(Permission.Read), token.perms().contains(Permission.Write),
                token.perms().contains(Permission.Delete));

        return tokenId;
    }

    @Override
    public Optional<Capability> read(Request request, String tokenId) {
        return database.findOptional(this::readToken, "SELECT path, r, w, d FROM caps WHERE cap_id = ?;",
                Util.hash(tokenId));
    }

    private Capability readToken(ResultSet resultSet) throws SQLException {
        var path = castNonNull(resultSet.getString("path"), "nonnull by db constraint");
        var perms = Permission.permsFrom(resultSet.getBoolean("r"), resultSet.getBoolean("w"),
                resultSet.getBoolean("d"));

        return new Capability(path, perms);
    }

    @Override
    public void revoke(Request request, String tokenId) {
        database.update("DELETE FROM caps WHERE cap_id = ?;", Util.hash(tokenId));
    }

    private String randomId() {
        var bytes = new byte[20];
        rng.nextBytes(bytes);
        return Base64Url.encode(bytes);
    }
}
