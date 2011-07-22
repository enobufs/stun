/*
 * Copyright (c) 2011 Yutaka Takeda <yt0916 at gmail.com>
 * MIT Licensed
 */

require.paths.unshift('../lib');
var stun = require('stun');

// Load config file.
var fs = require('fs');
eval(fs.readFileSync('stunServer.conf', encoding="ascii"));

var server = stun.createServer();
server.setAddress0(settings.STUN_SERVER_ADDR_0);
server.setAddress1(settings.STUN_SERVER_ADDR_1);
server.listen();

