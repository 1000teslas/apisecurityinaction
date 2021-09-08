package com.manning.apisecurityinaction.controller;

import java.text.MessageFormat;
import java.time.Instant;
import java.util.EnumSet;
import java.util.stream.Collectors;

import org.dalesbred.Database;
import org.json.JSONArray;
import org.json.JSONObject;

import spark.Request;
import spark.Response;

import static org.checkerframework.checker.nullness.util.NullnessUtil.castNonNull;

public class SpaceController {
    private final Database database;

    public SpaceController(Database database) {
        this.database = database;
    }

    public JSONObject createSpace(Request request, Response response) {
        var json = new JSONObject(request.body());
        var spaceName = json.getString("name");
        if (spaceName.length() > 255) {
            throw new IllegalArgumentException("space name too long");
        }

        String owner = castNonNull(request.attribute("subject"), "nonnull since authenticated");

        return database.withTransaction(tx -> {
            var spaceId = database.findUniqueLong("SELECT NEXT VALUE FOR space_id_seq;");

            database.updateUnique("INSERT INTO spaces(space_id, name, owner) VALUES(?, ?, ?);", spaceId, spaceName,
                    owner);

            database.updateUnique(
                    "INSERT INTO permissions(space_id, user_id, read, write, delete) VALUES (?, ?, true, true, true);",
                    spaceId, owner);

            response.status(201);
            var location = "/spaces/" + spaceId;
            response.header("Location", location);

            return new JSONObject().put("name", spaceName).put("uri", location);
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

            response.status(201);
            var location = MessageFormat.format("/spaces/{0}/messages/{1}", spaceId, msgId);
            response.header("Location", location);

            return new JSONObject().put("uri", location);
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
        var since1 = request.queryParams("since");
        var since = since1 == null ? null : Instant.parse(since1);

        var messages = since == null
                ? database.findAll(Long.class, "SELECT msg_id FROM messages WHERE space_id = ?;", spaceId)
                : database.findAll(Long.class, "SELECT msg_id FROM messages WHERE space_id = ?, msg_time >= ?;",
                        spaceId, since);

        response.status(200);
        return new JSONArray(
                messages.stream().map(msgId -> MessageFormat.format("/spaces/{0}/messages/{1}", spaceId, msgId))
                        .collect(Collectors.toList()));
    }

    public static class Message {
        private final long spaceId;
        private final long msgId;
        private final String author;
        private final Instant time;
        private final String message;

        public Message(long spaceId, long msgId, String author, Instant time, String message) {
            this.spaceId = spaceId;
            this.msgId = msgId;
            this.author = author;
            this.time = time;
            this.message = message;
        }

        @Override
        public String toString() {
            return new JSONObject().put("uri", MessageFormat.format("/spaces/{0}/messages/{1}", spaceId, msgId))
                    .put("author", author).put("time", time.toString()).put("message", message).toString();
        }
    }

    public JSONObject addMember(Request request, Response response) throws InsufficientPermissionsException {
        var json = new JSONObject(request.body());
        var spaceId = Long.parseLong(request.params(":spaceId"));
        var userToAdd = json.getString("username");
        var read = json.getBoolean("read");
        var write = json.getBoolean("write");
        var delete = json.getBoolean("delete");
        var permsWanted = Permission.permsFrom(read, write, delete);

        var username = castNonNull(request.attribute("subject"), "nonnull since authenticated");
        var permsHad = database.findOptional(Permission::permsFromRow,
                "SELECT read, write, delete FROM permissions WHERE space_id = ? AND user_id = ?;", spaceId, username)
                .orElse(EnumSet.noneOf(Permission.class));
        if (!permsHad.containsAll(permsWanted)) {
            throw new InsufficientPermissionsException();
        }

        database.updateUnique("INSERT INTO permissions(space_id, user_id, read, write, delete) VALUES (?, ?, ?, ?, ?);",
                spaceId, userToAdd, read, write, delete);

        response.status(200);
        return new JSONObject().put("username", userToAdd).put("read", read).put("write", write).put("delete", delete);
    }

    public class InsufficientPermissionsException extends Exception {
    }
}
