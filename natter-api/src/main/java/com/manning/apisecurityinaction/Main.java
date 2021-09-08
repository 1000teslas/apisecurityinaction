package com.manning.apisecurityinaction;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.EnumSet;
import java.util.Objects;

import com.google.common.util.concurrent.RateLimiter;
import com.manning.apisecurityinaction.controller.AuditController;
import com.manning.apisecurityinaction.controller.ModeratorController;
import com.manning.apisecurityinaction.controller.Permission;
import com.manning.apisecurityinaction.controller.SpaceController;
import com.manning.apisecurityinaction.controller.UserController;

import org.dalesbred.Database;
import org.dalesbred.result.EmptyResultException;
import org.h2.jdbcx.JdbcConnectionPool;
import org.json.JSONException;
import org.json.JSONObject;

import spark.Request;
import spark.Response;

import static spark.Spark.*;
import static org.checkerframework.checker.nullness.util.NullnessUtil.castNonNull;

public class Main {
    public static void main(String[] args) throws URISyntaxException, IOException {
        // trust store is optional
        secure("localhost.p12", "changeit", null, null);

        var dataSource = JdbcConnectionPool.create("jdbc:h2:mem:natter", "natter", "password");
        var database = Database.forDataSource(dataSource);
        createTables(database);
        dataSource = JdbcConnectionPool.create("jdbc:h2:mem:natter", "natter_api_user", "password");

        database = Database.forDataSource(dataSource);
        var spaceController = new SpaceController(database);
        var userController = new UserController(database);
        var auditController = new AuditController(database);
        var moderatorController = new ModeratorController(database);

        var rateLimiter = RateLimiter.create(2.0d);

        before((request, response) -> {
            if (!rateLimiter.tryAcquire()) {
                response.header("Retry-After", "2");
                halt(429);
            }
        });

        before((request, response) -> {
            if (request.requestMethod().equals("POST") && !"application/json".equals(request.contentType())) {
                halt(415, new JSONObject().put("error", "Only application/json supported").toString());
            }
        });

        afterAfter((request, response) -> {
            response.type("application/json;charset=utf-8");
            response.header("X-Content-Type-Options", "nosniff");
            response.header("X-Frame-Options", "DENY");
            response.header("X-XSS-Protection", "0");
            response.header("Cache-Control", "no-store");
            response.header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox");
            response.header("Server", "");
            response.header("Strict-Transport-Security", "max-age=31536000");
        });

        before(userController::authenticate);

        before(auditController::auditRequestStart);
        afterAfter(auditController::auditRequestEnd);

        before("/spaces", userController::requireAuthentication);
        post("/spaces", spaceController::createSpace);

        before("/spaces/:spaceId/messages", userController.requirePermission("POST", EnumSet.of(Permission.Write)));
        post("/spaces/:spaceId/messages", spaceController::postMessage);

        before("/spaces/:spaceId/messages/*", userController.requirePermission("GET", EnumSet.of(Permission.Read)));
        get("/spaces/:spaceId/messages/:msgId", spaceController::readMessage);

        before("/spaces/:spaceId/messages", userController.requirePermission("GET", EnumSet.of(Permission.Read)));
        get("/spaces/:spaceId/messages", spaceController::findMessages);

        before("/spaces/:spaceId/members", userController::requireAuthentication);
        post("/spaces/:spaceId/members", spaceController::addMember);

        before("/spaces/:spaceId/messages/*",
                userController.requirePermission("DELETE", EnumSet.of(Permission.Delete)));
        delete("/spaces/:spaceId/messages/:msgId", moderatorController::deletePost);

        get("/logs", auditController::readAuditLog);
        post("/users", userController::registerUser);

        internalServerError(new JSONObject().put("error", "internal server error").toString());
        notFound(new JSONObject().put("error", "not found").toString());

        exception(IllegalArgumentException.class, Main::badRequest);
        exception(JSONException.class, Main::badRequest);
        exception(EmptyResultException.class, (e, request, response) -> response.status(404));
        exception(SpaceController.InsufficientPermissionsException.class, (e, request, response) -> {
            response.status(403);
            response.body(new JSONObject()
                    .put("error", "attempted to create user with more permissions than current user").toString());
        });
    }

    private static void createTables(Database database) throws URISyntaxException, IOException {
        var path = Paths.get(
                castNonNull(Main.class.getResource("/schema.sql"), "resource \"/schema.sql\" does not exist").toURI());
        database.update(Files.readString(path));
    }

    private static void badRequest(Exception ex, Request request, Response response) {
        response.status(400);
        response.body(new JSONObject().put("error", Objects.requireNonNullElse(ex.getMessage(), "")).toString());
    }
}