package com.manning.apisecurityinaction.controller;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.EnumSet;
import java.util.stream.Collectors;

import org.dalesbred.Database;
import org.json.JSONArray;
import org.json.JSONObject;

import spark.Request;
import spark.Response;

import static java.text.MessageFormat.format;
import static org.checkerframework.checker.nullness.util.NullnessUtil.castNonNull;

public record SpaceController(Database database, CapabilityController capabilityController) {

    public JSONObject createSpace(Request request, Response response) {
        var json = new JSONObject(request.body());
        var spaceName = json.getString("name");
        if (spaceName.length() > 255) {
            throw new IllegalArgumentException("space name too long");
        }

        var owner = castNonNull(request.attribute("subject"), "nonnull since authenticated");

        return database.withTransaction(tx -> {
            var spaceId = database.findUniqueLong("SELECT NEXT VALUE FOR space_id_seq;");

            database.updateUnique("INSERT INTO spaces(space_id, name, owner) VALUES(?, ?, ?);", spaceId, spaceName,
                    owner);

            var uri = capabilityController.createUri(request, "/spaces/" + spaceId,
                    EnumSet.of(Permission.Read, Permission.Write, Permission.Delete));
            var messagesUri = capabilityController.createUri(request, format("/spaces/{0}/messages", spaceId),
                    EnumSet.of(Permission.Read, Permission.Write, Permission.Delete));
            var messagesRwUri = capabilityController.createUri(request, format("/spaces/{0}/messages", spaceId),
                    EnumSet.of(Permission.Read, Permission.Write));
            var messagesRoUri = capabilityController.createUri(request, format("/spaces/{0}/messages", spaceId),
                    EnumSet.of(Permission.Read));

            response.status(201);
            response.header("Location", uri.toASCIIString());

            return new JSONObject().put("name", spaceName).put("uri", uri).put("messages-rwd", messagesUri)
                    .put("messages-rw", messagesRwUri).put("messages-r", messagesRoUri);
        });
    }

    public JSONObject postMessage(Request request, Response response) {
        var spaceId = Long.parseLong(request.params(":spaceId"));
        String author = castNonNull(request.attribute("subject"), "nonnull since authenticated");
        var json = new JSONObject(request.body());
        var message = json.getString("message");
        if (message.length() > 1024) {
            throw new IllegalArgumentException("message text too long");
        }

        return database.withTransaction(tx -> {
            var msgId = database.findUniqueLong("SELECT NEXT VALUE FOR msg_id_seq;");

            database.updateUnique(
                    "INSERT INTO messages(space_id, msg_id, author, msg_time, msg_text) VALUES(?, ?, ?, current_timestamp, ?);",
                    spaceId, msgId, author, message);

            var uri = capabilityController.createUri(request, format("/spaces/{0}/messages/{1}", spaceId, msgId),
                    EnumSet.of(Permission.Read, Permission.Write, Permission.Delete));
            var roUri = capabilityController.createUri(request, format("/spaces/{0}/messages/{1}", spaceId, msgId),
                    EnumSet.of(Permission.Read));

            response.status(201);
            response.header("Location", uri.toASCIIString());

            return new JSONObject().put("uri", uri).put("uri-ro", roUri);
        });
    }

    public Message readMessage(Request request, Response response) {
        var spaceId = Long.parseLong(request.params(":spaceId"));
        var msgId = Long.parseLong(request.params(":msgId"));

        var message = database.findUnique(Message.class,
                "SELECT space_id, msg_id, author, msg_time, msg_text FROM messages WHERE msg_id = ? AND space_id = ?",
                msgId, spaceId);

        response.status(200);
        return message;
    }

    public JSONArray findMessages(Request request, Response response) {
        var spaceId = Long.parseLong(request.params(":spaceId"));
        var since = Instant.now().minus(1, ChronoUnit.DAYS);
        if (request.queryParams("since") != null) {
            since = Instant.parse(request.queryParams("since"));
        }

        var messages = database.findAll(Long.class, "SELECT msg_id FROM messages WHERE space_id = ? AND msg_time >= ?;",
                spaceId, since);
        EnumSet<Permission> perms = castNonNull(request.attribute("perms"),
                "nonnull since checked in requirePermission");

        response.status(200);
        return new JSONArray(messages.stream().map(msgId -> {
            var path = format("/spaces/{0}/messages/{1}", spaceId, msgId);
            return capabilityController.createUri(request, path, perms);
        }).collect(Collectors.toList()));
    }

    public static record Message(long spaceId, long msgId, String author, Instant time, String message) {
        @Override
        public String toString() {
            return new JSONObject().put("uri", format("/spaces/{0}/messages/{1}", spaceId, msgId)).put("author", author)
                    .put("time", time.toString()).put("message", message).toString();
        }
    }
}
