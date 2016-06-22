"use strict";

var validateGrantTokenRequest = require("../common/validateGrantTokenRequest");
var finishGrantingToken = require("../common/finishGrantingToken");
var makeOAuthError = require("../common/makeOAuthError");

module.exports = function grantToken(req, res, next, options) {
    function sendUnauthorizedError(type, description) {
        res.header("WWW-Authenticate", "Basic realm=\"" + description + "\"");
        next(makeOAuthError("Unauthorized", type, description));
    }

    if (!validateGrantTokenRequest("password", req, next)) {
        return;
    }

    var message = "";
    var username = req.body.username;
    var password = req.body.password;

    if (!username) {
        message = "Must specify username field.";
        if (options.msg ) message = options.msg.oauth.missing.username;
        return next(makeOAuthError("BadRequest", "invalid_request", message ));
    }

    if (!password) {
        message = "Must specify password field.";
        if (options.msg ) message = options.msg.oauth.missing.password;
        return next(makeOAuthError("BadRequest", "invalid_request", message));
    }

    var clientId = req.authorization.basic.username;
    var clientSecret = req.authorization.basic.password;
    var clientCredentials = { clientId: clientId, clientSecret: clientSecret };

    options.hooks.validateClient(clientCredentials, req, function (error, result) {
        if (error) {
            return next(error);
        }

        if (!result) {
            message = "Client ID and secret did not validate.";
            if (options.msg ) message = options.msg.oauth.missing.client;
            return sendUnauthorizedError("invalid_client", message );
        }

        var allCredentials = { clientId: clientId, clientSecret: clientSecret, username: username, password: password };
        options.hooks.grantUserToken(allCredentials, req, function (error, token) {
            if (error) {
                return next(error);
            }

            if (!token) {
                message = "Username and password did not authenticate.";
                if (options.msg ) message = options.msg.oauth.missmatch;
                return sendUnauthorizedError("invalid_grant", message );
            }

            var allCredentials = {
                clientId: clientId,
                clientSecret: clientSecret,
                username: username,
                password: password,
                token: token
            };
            finishGrantingToken(allCredentials, token, options, req, res, next);
        });
    });
};
