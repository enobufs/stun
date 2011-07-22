/*
 * Copyright (c) 2011 Yutaka Takeda <yt0916 at gmail.com>
 * MIT Licensed
 */

require.paths.unshift('../src');
var stun = require('stun');

//var STUN_SERVER_ADDR = "dntg-stun.usrd.scea.com";
//var STUN_SERVER_ADDR = "stun1.noc.ams-ix.net";
var STUN_SERVER_ADDR = "172.16.4.6";

var client = stun.createClient();
client.setServerAddr(STUN_SERVER_ADDR);
client.start(function(result) {
        var mapped = client.getMappedAddr();
        console.log("Complete(" + result + "): " + (client.isNatted()?"Natted":"Open") + " NB=" + client.getNB() + " EF=" + client.getEF() + " (" + client.getNatType() + ") mapped=" + mapped.address + ":" + mapped.port + " rtt=" + client.getRtt());
        client.close(function() {
            console.log("All sockets closed.");});});

