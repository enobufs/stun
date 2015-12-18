/*
 * Copyright (c) 2011 Yutaka Takeda <yt0916 at gmail.com>
 * MIT Licensed
 */

var stun = require('../lib/stun.js');

// Load config file.
var fs = require('fs');
eval(fs.readFileSync('stunServer.conf', encoding="ascii"));

var server = stun.createServer();

server.setAddress0(settings.STUN_SERVER_ADDR_0);
server.setAddress1(settings.STUN_SERVER_ADDR_1);
server.listen();

// Server with optional callback:
/*
server.listen(function ()
	{
		console.log("listening with socket ", this);
	});
*/	

