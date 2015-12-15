#!/usr/bin/env node
'use strict';

// Load config (ini) file.
var config = (function () {
    var fs = require('fs');
    var path = require('path');
    var ini = require('ini');
    var _ = require('lodash');

    var root = process.cwd();
    var iniPath = path.join(root, 'node-stun.ini');
    var config = {};
    try {
        config = ini.parse(fs.readFileSync(iniPath, 'utf-8'));
    } catch (e) {
        if (e.code === 'ENOENT') {
            console.warn('Config file not found:', e);
        } else {
            throw e;
        }
    }
    var defaults = {
        primary: {
            host: '127.0.0.1',
            port: '3478'
        },
        secondary: {
            host: '127.0.0.2',
            port: '3479'
        }
    };

    return _.defaultsDeep(config, defaults);
})();



var stun = require('../index');
var server = stun.createServer(config);

// Set log event handler
server.on('log', function (log) {
    console.log('%s : [%s] %s', new Date(), log.level, log.message);
});

// Start listening
server.listen();

