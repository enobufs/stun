'use strict';

var dgram = require('dgram');
var util = require('util');
var EventEmitter = require('events').EventEmitter;

var Message = require('./message');

/**
 * Server class.
 * @class
 * @param {object} config Config object.
 * @param {object} config.primary Primary address
 * @param {string} config.primary.host Primary host name
 * @param {string|number} config.primary.port Primary port number
 * @param {object} config.secondary Secondary address
 * @param {string} config.secondary.host Secondary host name
 * @param {string|number} config.secondary.port Secondary port number
 */
function Server(config) {
    this._addr0 = config.primary.host;
    this._addr1 = config.secondary.host;
    this._port0 = parseInt(config.primary.port);
    this._port1 = parseInt(config.secondary.port);
    this._sockets = [];
    this._stats = {
        numRcvd: 0,
        numSent: 0,
        numMalformed: 0,
        numUnsupported: 0
    };
    this._logger = require('./logger').create(this);
}

util.inherits(Server, EventEmitter);

/** @private */
Server.prototype._onListening = function (sid) {
    var sin = this._sockets[sid].address();
    this._logger.info("soc[" + sid + "] listening on " + sin.address + ":" + sin.port);
};

Server.prototype._onReceived = function (sid, msg, rinfo) {
    this._logger.debug("soc[" + sid + "] received from " + rinfo.address + ":" + rinfo.port);

    var stunmsg = new Message();
    var fid = sid; // source socket ID for response

    this._stats.numRcvd++;

    try {
        stunmsg.deserialize(msg);
    }
    catch (e) {
        this._stats.numMalformed++;
        this._logger.warn("Error: " + e.message);
        return;
    }

    // We are only interested in binding request.
    if (stunmsg.getType() != 'breq') {
        this._stats.numUnsupported++;
        return;
    }

    var val;

    // Modify source socket ID (fid) based on
    // CHANGE-REQUEST attribute.
    val = stunmsg.getAttribute('changeReq');
    if (val != undefined) {
        if (val.changeIp) {
            fid ^= 0x2;
        }
        if (val.changePort) {
            fid ^= 0x1;
        }
    }

    // Check if it has timestamp attribute.
    var txTs;
    var rcvdAt = Date.now();
    val = stunmsg.getAttribute('timestamp');
    if (val != undefined) {
        txTs = val.timestamp;
    }

    //this._logger.debug("sid=" + sid + " fid=" + fid);

    try {
        // Initialize the message object to reuse.
        // The init() does not reset transaction ID.
        stunmsg.init();
        stunmsg.setType('bres');

        // Add mapped address.
        stunmsg.addAttribute('mappedAddr', {
            'family': 'ipv4',
            'port': rinfo.port,
            'addr': rinfo.address
        });

        // Offer CHANGED-ADDRESS only when this._addr1 is defined.
        if (this._addr1 != undefined) {
            var chAddr = (sid & 0x2)? this._addr0:this._addr1;
            var chPort = (sid & 0x1)?this._port0:this._port1;

            stunmsg.addAttribute('changedAddr', {
                'family': 'ipv4',
                'port': chPort,
                'addr': chAddr
            });
        }

        var soc = this._sockets[fid];

        // Add source address.
        stunmsg.addAttribute('sourceAddr', {
            'family': 'ipv4',
            'port': soc.address().port,
            'addr': soc.address().address
        });

        // Add timestamp if existed in the request.
        if (txTs) {
            stunmsg.addAttribute('timestamp', {
                'respDelay': ((Date.now() - rcvdAt) & 0xffff),
                'timestamp': txTs
            });
        }

        var resp = stunmsg.serialize();
        if (!soc) {
            throw new Error("Invalid from ID: " + fid);
        }

        this._logger.debug('soc[' + fid + '] sending ' + resp.length + ' bytes to ' + rinfo.address + ':' + rinfo.port);
        soc.send(   resp,
                    0,
                    resp.length,
                    rinfo.port,
                    rinfo.address);
    } catch (e) {
        this._stats.numMalformed++;
        this._logger.debug("Error: " + e.message);
    }

    this._stats.numSent++;
};

Server.prototype._getPort = function (sid) {
    return (sid & 1)? this._port1:this._port0;
};

Server.prototype._getAddr = function (sid) {
    return (sid & 2)? this._addr1:this._addr0;
};

/**
 * Starts listening to STUN requests from clients.
 * @throws {Error} Server address undefined.
 */
Server.prototype.listen = function () {
    var self = this;

    // Sanity check
    if (!this._addr0) {
        throw new Error("Address undefined");
    }
    if (!this._addr1) {
        throw new Error("Address undefined");
    }

    for (var i = 0; i < 4; ++i) {
        // Create socket and add it to socket array.
        var soc = dgram.createSocket("udp4");
        this._sockets.push(soc);

        switch (i) {
            case 0:
                soc.on("listening", function () { self._onListening(0); });
                soc.on("message", function (msg, rinfo) { self._onReceived(0, msg, rinfo); });
                break;
            case 1:
                soc.on("listening", function () { self._onListening(1); });
                soc.on("message", function (msg, rinfo) { self._onReceived(1, msg, rinfo); });
                break;
            case 2:
                soc.on("listening", function () { self._onListening(2); });
                soc.on("message", function (msg, rinfo) { self._onReceived(2, msg, rinfo); });
                break;
            case 3:
                soc.on("listening", function () { self._onListening(3); });
                soc.on("message", function (msg, rinfo) { self._onReceived(3, msg, rinfo); });
                break;
            default:
                throw new RangeError("Out of socket array");
        }

        // Start listening.
        soc.bind(self._getPort(i), self._getAddr(i));
    }
};

/**
 * Closes the STUN server.
 */
Server.prototype.close = function () {
    while (this._sockets.length > 0) {
        var soc = this._sockets.shift();
        var sin = soc.address();
        this._logger.info("Closing socket on " + sin.address + ":" + sin.port);
        soc.close();
    }
};

module.exports = Server;
