#!/usr/bin/env node
'use strict';

var Client = require('../index').Client;
var STUN_SERVER_ADDR = "127.0.0.1";

var client = new Client();
client.setServerAddr(STUN_SERVER_ADDR);
client.setLocalAddr('127.0.0.1');
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

