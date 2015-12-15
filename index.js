'use strict';

exports.createServer = function (config) {
    var Server = require('./lib/server');
    return new Server(config);
};

exports.createClient = function () {
    var Client = require('./lib/client');
    return new Client();
};
