#!/usr/bin/env node
'use strict';

var stun = require('../index');
var serverAddr = "127.0.0.1";

var program = require('commander');

program
.version(require('../package').version)
.option('-s, --server [host]', 'STUN server address (e.g. 24.1.2.3')
.option('-p, --port [port]', 'STUN server port', '3478')
.parse(process.argv);

if (program.server) {
    serverAddr = program.server;
}


var client = stun.createClient();
client.setServerAddr(serverAddr, +program.port);
client.start(function (result) {
    var mapped = client.getMappedAddr();
    console.log([
        "Complete(" + result + "): ",
        (client.isNatted()?"Natted":"Open"),
        " NB=" + client.getNB(),
        " EF=" + client.getEF(),
        " (" + client.getNatType() + ")",
        " mapped=" + mapped.address + ":" + mapped.port,
        " rtt=" + client.getRtt()
    ].join(''));

    client.close(function () {
        console.log("All sockets closed.");
    });
});

