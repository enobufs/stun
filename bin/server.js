#!/usr/bin/env node
'use strict';

var Server = require('../index').Server;
// var Server = require('node-stun').Server;

var server = new Server();

// Set log event handler
server.on('log', function (log) {
    console.log('%s : [%s] %s', new Date(), log.level, log.message);
});

// Start listening
server.listen();

