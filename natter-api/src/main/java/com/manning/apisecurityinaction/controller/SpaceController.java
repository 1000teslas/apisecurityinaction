package com.manning.apisecurityinaction.controller;

import org.dalesbred.Database;
import org.json.JSONObject;

import spark.Request;
import spark.Response;

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
        var owner = json.getString("owner");
        var subject = request.attribute("subject");
        if (!owner.equals(subject)) {
            throw new IllegalArgumentException("owner must match authenticated user");
        }

        return database.withTransaction(tx -> {
            var spaceId = database.findUniqueLong("SELECT NEXT VALUE FOR space_id_seq;");

            database.updateUnique("INSERT INTO spaces(space_id, name, owner) VALUES(?, ?, ?);", spaceId, spaceName,
                    owner);

            response.status(201);
            response.header("Location", "/spaces/" + spaceId);

            return new JSONObject().put("name", spaceName).put("uri", "/spaces/" + spaceId);
        });
    }
}
