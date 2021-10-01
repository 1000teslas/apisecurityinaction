package com.manning.apisecurityinaction.token;

import java.security.SecureRandom;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.manning.apisecurityinaction.controller.Permission;

import org.dalesbred.Database;

import spark.Request;

import static org.checkerframework.checker.nullness.util.NullnessUtil.castNonNull;

public final class CapabilityStore implements ConfidentialTokenStore<Capability> {
    private final Database database;
    private final SecureRandom rng;

    public CapabilityStore(Database database, SecureRandom rng) {
        this.database = database;
        this.rng = rng;
        // this can only be guaranteed initialized if there are no subclasses
        Executors.newSingleThreadScheduledExecutor().scheduleAtFixedRate(this::deleteExpiredTokens, 10, 10,
                TimeUnit.MINUTES);
    }

    public String create(Request request, Capability token) {
        var tokenId = randomId();

        database.updateUnique("INSERT INTO caps(cap_id, expiry, path, r, w, d) VALUES(?, ?, ?, ?, ?, ?);",
                Util.hash(tokenId), token.expiry(), token.path(), token.perms().contains(Permission.Read),
                token.perms().contains(Permission.Write), token.perms().contains(Permission.Delete));

        return tokenId;
    }

    public Optional<Capability> read(Request request, String tokenId) {
        return database.findOptional(this::readToken, "SELECT expiry, path, r, w, d FROM caps WHERE cap_id = ?;",
                Util.hash(tokenId));
    }

    private Capability readToken(ResultSet resultSet) throws SQLException {
        var ts = resultSet.getTimestamp("expiry");
        var expiry = ts == null ? null : ts.toInstant();
        var path = castNonNull(resultSet.getString("path"), "nonnull by db constraint");
        var perms = Permission.permsFrom(resultSet.getBoolean("r"), resultSet.getBoolean("w"),
                resultSet.getBoolean("d"));

        return new Capability(expiry, path, perms);
    }

    public void revoke(Request request, String tokenId) {
        database.update("DELETE FROM caps WHERE cap_id = ?;", Util.hash(tokenId));
    }

    private String randomId() {
        var bytes = new byte[20];
        rng.nextBytes(bytes);
        return Base64Url.encode(bytes);
    }

    public void deleteExpiredTokens() {
        database.update("DELETE FROM caps WHERE expiry < current_timestamp;");
    }
}
