'use strict';

var dns = require('dns');
var dgram = require('dgram');
var crypto = require('crypto');
var Const = require('./const');
var Utils = require('./utils');
var Message = require('./message');

// Client state
var State = Object.freeze({
    //                src   dst  chIp chPort  breq
    IDLE    : 0, //  -----  ---- ---- ------ ------
    RESOLV  : 1, //    -     -     -    -       -
    NBDaDp  : 2, //  _soc0  DaDp   0    0    _breq0
    NBDaCp  : 3, //  _soc0  DaCp   0    0    _breq0
    NBCaDp  : 4, //  _soc0  CaDp   0    0    _breq0
    NBCaCp  : 5, //  _soc0  CaCp   0    0    _breq0
    EFDiscov: 6, //  _soc0  DaDp   1    1    _breq0
                 //  _soc0  DaDp   1    0    _breq1
    COMPLETE: 7
});

function Rtt() {
    this._sum = 0;
    this._num = 0;
    this.init = function () { this._sum = 0; this._num = 0; };
    this.addSample = function (rtt) { this._sum += rtt; this._num++; };
    this.get = function () { return this._num?(this._sum/this._num):0; };
}

/**
 * Client class.
 * @class
 * @see stun.createClient()
 */
function Client() {
    this._domain; // FQDN
    this._serv0; // Dotted decimal.
    this._serv1; // Dotted decimal.
    this._port0 = 3478;
    this._port1; // Obtained via CHANGE-ADDRESS
    this._local = { addr:'0.0.0.0', port:0 };
    this._soc0;
    this._soc1;
    this._breq0; // Binding request 0 of type Message.
    this._breq1; // Binding request 1 of type Message.
    this._state = State.IDLE;
    this._mapped = [
        { addr:0, port:0 },  // mapped addr from DaDp
        { addr:0, port:0 },  // mapped addr from DaCp
        { addr:0, port:0 },  // mapped addr from CaDp
        { addr:0, port:0 }]; // mapped addr from CaCp
    // pd ad
    //  0  0 : Independent
    //  0  1 : Address dependent
    //  1  0 : Port dependent (rare)
    //  1  1 : Address & port dependent
    // -1  * : pd check in progress
    //  * -1 : ad check in progress
    this._ef = { ad: undefined, pd: undefined };
    this._numSocs = 0;
    this._cbOnComplete;
    this._cbOnClosed;
    this._intervalId;
    this._retrans = 0; // num of retransmissions
    this._elapsed = 0; // *100 msec
    this._mode = Const.Mode.FULL;
    this._rtt = new Rtt();
}

/**
 * @private
 * @static
 */
Client._isLocalAddr = function (addr, cb) {
    var dummy = dgram.createSocket('udp4');
    dummy.bind(0, addr, function () {
        dummy.close();
        cb(null, true);
    });
    dummy.on('error', function (err) {
        if (err.code !== 'EADDRNOTAVAIL') {
            return cb(err);
        }
        cb(null, false);
    });
};

Client.prototype._discover = function () {
    var self = this;
    var Ctor = this.constructor;
    // Create socket 0.
    this._soc0 = dgram.createSocket("udp4");
    this._soc0.on("listening", function () {
        self._onListening();
    });
    this._soc0.on("message", function (msg, rinfo) {
        self._onReceived(msg, rinfo);
    });
    this._soc0.on("close", function () {
        self._onClosed();
    });

    // Start listening on the local port.
    this._soc0.bind(0, this._local.addr, function () {
        // Get assigned port name for this socket.
        self._local.addr = self._soc0.address().address;
        self._local.port = self._soc0.address().port;

        self._breq0 = new Message();
        self._breq0.init();
        self._breq0.setType('breq');
        self._breq0.setTransactionId(Ctor._randTransId());
        /*
        self._breq0.addAttribute('timestamp', {
            'respDelay': 0,
            'timestamp': (Date.now() & 0xffff)
        });
        */

        var msg = self._breq0.serialize();
        self._soc0.send(msg, 0, msg.length, self._port0, self._serv0);

        self._retrans = 0;
        self._elapsed = 0;
        self._intervalId = setInterval(function () {
            self._onTick();
        }, 100);
        self._state = State.NBDaDp;
    });
};

Client.prototype._onResolved = function (err, addresses) {
    if (err) {
        if (this._cbOnComplete != undefined) {
            this._cbOnComplete(Const.Result.HOST_NOT_FOUND);
        }
        return;
    }

    this._serv0 = addresses[0];
    this._discover();
};

Client.prototype._onListening = function () {
    this._numSocs++;
    //console.log("this._numSocs++: " + this._numSocs);
};

Client.prototype._onClosed = function () {
    if (this._numSocs > 0) {
        this._numSocs--;
        //console.log("this._numSocs--: " + this._numSocs);
        if (this._cbOnClosed != undefined && !this._numSocs) {
            this._cbOnClosed();
        }
    }
};

Client.prototype._onTick = function () {
    var sbuf;

    // this._retrans this._elapsed
    //    0       1( 1)  == Math.min((1 << this._retrans), 16)
    //    1       2( 3)
    //    2       4( 7)
    //    3       8(15)
    //    4      16(31)
    //    5      16(47)
    //    6      16(63)
    //    7      16(79)
    //    8      16(95)

    this._elapsed++;

    if (this._elapsed >= Math.min((1 << this._retrans), 16)) {
        // Retransmission timeout.
        this._retrans++;
        this._elapsed = 0;

        if (this._state == State.NBDaDp ||
            this._state == State.NBDaCp ||
            this._state == State.NBCaDp ||
            this._state == State.NBCaCp) {
            if (this._retrans < 9) {
                /*
                this._breq0.addAttribute('timestamp', {
                    'respDelay': 0,
                    'timestamp': (Date.now() & 0xffff)
                });
                */
                sbuf = this._breq0.serialize();
                var toAddr;
                var toPort;

                switch (this._state) {
                    case State.NBDaDp:
                        toAddr = this._serv0; toPort = this._port0;
                        break;
                    case State.NBDaCp:
                        toAddr = this._serv0; toPort = this._port1;
                        break;
                    case State.NBCaDp:
                        toAddr = this._serv1; toPort = this._port0;
                        break;
                    case State.NBCaCp:
                        toAddr = this._serv1; toPort = this._port1;
                        break;
                }

                this._soc0.send(sbuf, 0, sbuf.length, toPort, toAddr);
                console.log(
                        "NB-Rtx0: len=" + sbuf.length +
                        " retrans=" + this._retrans +
                        " elapsed=" + this._elapsed +
                        " to=" + toAddr +
                        ":" + toPort);
            }
            else {
                clearInterval(this._intervalId);
                var firstNB = (this._state == State.NBDaDp);
                this._state = State.COMPLETE;

                if (this._cbOnComplete != undefined) {
                    if (firstNB) {
                        this._cbOnComplete(Const.Result.UDP_BLOCKED);
                    }
                    else {
                        // First binding succeeded, then subsequent
                        // binding should work, but didn't.
                        this._cbOnComplete(Const.Result.NB_INCOMPLETE);
                    }
                }
            }
        }
        else if (this._state == State.EFDiscov) {
            if (this._ef.ad == undefined) {
                if (this._retrans < 9) {
                    sbuf = this._breq0.serialize();
                    this._soc1.send(sbuf, 0, sbuf.length, this._port0, this._serv0);
                    console.log("EF-Rtx0: retrans=" + this._retrans + " elapsed=" + this._elapsed);
                }
                else {
                    this._ef.ad = 1;
                }
            }
            if (this._ef.pd == undefined) {
                if (this._retrans < 9) {
                    sbuf = this._breq1.serialize();
                    this._soc1.send(sbuf, 0, sbuf.length, this._port0, this._serv0);
                    console.log("EF-Rtx1: retrans=" + this._retrans + " elapsed=" + this._elapsed);
                }
                else {
                    this._ef.pd = 1;
                }
            }
            if (this._ef.ad != undefined && this._ef.pd != undefined) {
                clearInterval(this._intervalId);
                this._state = State.COMPLETE;
                if (this._cbOnComplete != undefined) {
                    this._cbOnComplete(Const.Result.OK);
                }
            }
        }
        else {
            console.log("Warning: unexpected timer event. Forgot to clear timer?");
            clearInterval(this._intervalId);
        }
    }
};

Client.prototype._onReceived = function (msg, rinfo) {
    var self = this;
    var Ctor = this.constructor;
    var bres = new Message();
    var val;
    var now = Date.now();
    var sbuf;
    void rinfo;

    try {
        bres.deserialize(msg);
    } catch (e) {
        console.log("Error: " + e.message);
        return;
    }

    // We are only interested in binding response.
    if (bres.getType() != 'bres') {
        return;
    }

    if (this._state == State.NBDaDp) {
        if (!Utils.bufferCompare(bres.getTransactionId(), this._breq0.getTransactionId())) {
            return; // discard
        }

        clearInterval(this._intervalId);

        // Get MAPPED-ADDRESS value.
        val = bres.getAttribute('mappedAddr');
        if (val == undefined) {
            console.log("Error: MAPPED-ADDRESS not present");
            return;
        }
        this._mapped[0].addr = val.addr;
        this._mapped[0].port = val.port;

        // Check if the mappped address is a local or not (natted)
        if (this._local.addr === '0.0.0.0') {
            Ctor._isLocalAddr(this._mapped[0].addr, function (err, isLocal) {
                if (!err) {
                    self._isNatted = !isLocal;
                }
            });
        } else {
            this._isNatted = (this._mapped[0].addr !== this._local.addr);
        }


        // Get CHANGED-ADDRESS value.
        val = bres.getAttribute('changedAddr');
        if (val == undefined) {
            console.log("Error: CHANGED-ADDRESS not present");
            return;
        }
        console.log('CHANGED: addr=%s:%d', val.addr, val.port);
        this._serv1 = val.addr;
        this._port1 = val.port;

        // Calculate RTT if timestamp is attached.
        val = bres.getAttribute('timestamp');
        if (val != undefined) {
            this._rtt.addSample(((now & 0xffff) - val.timestamp) - val.respDelay);
        }

        console.log("MAPPED0: addr=" + this._mapped[0].addr + ":" + this._mapped[0].port);
        //console.log("CHANGED: addr=" + this._serv1 + ":" + this._port1);

        // Start NBDaCp.
        this._breq0.init();
        this._breq0.setType('breq');
        this._breq0.setTransactionId(Ctor._randTransId());
        /*
        this._breq0.addAttribute('timestamp', {
            'respDelay': 0,
            'timestamp': (now & 0xffff)
        });
        */
        sbuf = this._breq0.serialize();
        this._soc0.send(sbuf, 0, sbuf.length, this._port1, this._serv0);

        this._retrans = 0;
        this._elapsed = 0;
        this._intervalId = setInterval(function () {
            self._onTick();
        }, 100);
        this._state = State.NBDaCp;
    }
    else if (this._state == State.NBDaCp) {
        if (!Utils.bufferCompare(bres.getTransactionId(), this._breq0.getTransactionId())) {
            return; // discard
        }

        clearInterval(this._intervalId);

        // Get MAPPED-ADDRESS value.
        val = bres.getAttribute('mappedAddr');
        if (val == undefined) {
            console.log("Error: MAPPED-ADDRESS not present");
            return;
        }
        this._mapped[1].addr = val.addr;
        this._mapped[1].port = val.port;

        // Calculate RTT if timestamp is attached.
        val = bres.getAttribute('timestamp');
        if (val != undefined) {
            this._rtt.addSample(((now & 0xffff) - val.timestamp) - val.respDelay);
        }

        console.log("MAPPED1: addr=" + this._mapped[1].addr + ":" + this._mapped[1].port);

        // Start NBCaDp.
        this._breq0.init();
        this._breq0.setType('breq');
        this._breq0.setTransactionId(Ctor._randTransId());
        /*
        this._breq0.addAttribute('timestamp', {
            'respDelay': 0,
            'timestamp': (now & 0xffff)
        });
        */
        sbuf = this._breq0.serialize();
        this._soc0.send(sbuf, 0, sbuf.length, this._port0, this._serv1);

        this._retrans = 0;
        this._elapsed = 0;
        this._intervalId = setInterval(function () {
            self._onTick();
        }, 100);
        this._state = State.NBCaDp;
    }
    else if (this._state == State.NBCaDp) {
        if (!Utils.bufferCompare(bres.getTransactionId(), this._breq0.getTransactionId())) {
            return; // discard
        }

        clearInterval(this._intervalId);

        // Get MAPPED-ADDRESS value.
        val = bres.getAttribute('mappedAddr');
        if (val == undefined) {
            console.log("Error: MAPPED-ADDRESS not present");
            return;
        }
        this._mapped[2].addr = val.addr;
        this._mapped[2].port = val.port;

        // Calculate RTT if timestamp is attached.
        val = bres.getAttribute('timestamp');
        if (val != undefined) {
            this._rtt.addSample(((now & 0xffff) - val.timestamp) - val.respDelay);
        }

        console.log("MAPPED2: addr=" + this._mapped[2].addr + ":" + this._mapped[2].port);

        // Start NBCaCp.
        this._breq0.init();
        this._breq0.setType('breq');
        this._breq0.setTransactionId(Ctor._randTransId());
        /*
        this._breq0.addAttribute('timestamp', {
            'respDelay': 0,
            'timestamp': (now & 0xffff)
        });
        */
        sbuf = this._breq0.serialize();
        this._soc0.send(sbuf, 0, sbuf.length, this._port1, this._serv1);

        this._retrans = 0;
        this._elapsed = 0;
        this._intervalId = setInterval(function () {
            self._onTick();
        }, 100);
        this._state = State.NBCaCp;
    }
    else if (this._state == State.NBCaCp) {
        if (!Utils.bufferCompare(bres.getTransactionId(), this._breq0.getTransactionId())) {
            return; // discard
        }

        clearInterval(this._intervalId);

        // Get MAPPED-ADDRESS value.
        val = bres.getAttribute('mappedAddr');
        if (val == undefined) {
            console.log("Error: MAPPED-ADDRESS not present");
            return;
        }
        this._mapped[3].addr = val.addr;
        this._mapped[3].port = val.port;

        // Calculate RTT if timestamp is attached.
        val = bres.getAttribute('timestamp');
        if (val != undefined) {
            this._rtt.addSample(((now & 0xffff) - val.timestamp) - val.respDelay);
        }

        console.log("MAPPED3: addr=" + this._mapped[3].addr + ":" + this._mapped[3].port);

        // Start NBDiscov.
        this._ef.ad = undefined;
        this._ef.pd = undefined;

        // Create another socket (this._soc1) from which EFDiscov is performed).
        this._soc1 = dgram.createSocket("udp4");
        this._soc1.on("listening", function () {
            self._onListening();
        });
        this._soc1.on("message", function (msg, rinfo) {
            self._onReceived(msg, rinfo);
        });
        this._soc1.on("close", function () {
            self._onClosed();
        });

        // Start listening on the local port.
        this._soc1.bind(0, this._local.addr);

        // changeIp=true,changePort=true from this._soc1
        this._breq0.init();
        this._breq0.setType('breq');
        this._breq0.setTransactionId(Ctor._randTransId());
        this._breq0.addAttribute('changeReq', {
            'changeIp': true,
            'changePort': true
        });

        sbuf = this._breq0.serialize();
        this._soc1.send(sbuf, 0, sbuf.length, this._port0, this._serv0);

        // changeIp=false,changePort=true from this._soc1
        this._breq1 = new Message();
        this._breq1.setType('breq');
        this._breq1.setTransactionId(Ctor._randTransId());
        this._breq1.addAttribute('changeReq', {
            'changeIp': false,
            'changePort': true
        });

        sbuf = this._breq1.serialize();
        this._soc1.send(sbuf, 0, sbuf.length, this._port0, this._serv0);

        this._retrans = 0;
        this._elapsed = 0;
        this._intervalId = setInterval(function () {
            self._onTick();
        }, 100);
        this._state = State.EFDiscov;
    }
    else if (this._state == State.EFDiscov) {
        var res = -1;
        if (this._ef.ad == undefined) {
            if (Utils.bufferCompare(bres.getTransactionId(), this._breq0.getTransactionId())) {
                res = 0;
            }
        }
        if (res < 0 && this._ef.pd == undefined) {
            if (Utils.bufferCompare(bres.getTransactionId(), this._breq1.getTransactionId())) {
                res = 1;
            }
        }

        if (res < 0) {
            return; // discard
        }

        if (res == 0) {
            this._ef.ad = 0;
        } else {
            this._ef.pd = 0;
        }

        if (this._ef.ad !== undefined && this._ef.pd !== undefined) {
            clearInterval(this._intervalId);
            this._state = State.COMPLETE;
            if (this._cbOnComplete) {
                this._cbOnComplete(Const.Result.OK);
            }
        }
    }
    else {
        return; // discard
    }

};

/**
 * @private
 * @static
 * @returns {Buffer} Returns a 16-random-bytes.
 */
Client._randTransId = function () {
    var seed = process.pid.toString(16);
    seed += Math.round(Math.random() * 0x100000000).toString(16);
    seed += (new Date()).getTime().toString(16);
    var md5 = crypto.createHash('md5');
    md5.update(seed);
    return md5.digest();
};

/**
 * Sets local address. Use of this method is optional. If your
 * local device has more then one interfaces, you can specify
 * one of these interfaces form which STUN is performed.
 * @param {string} addr Local IP address.
 * @throws {Error} The address not available.
 */
Client.prototype.setLocalAddr = function (addr) {
    this._local.addr = addr;
    this._local.port = 0;
};

/**
 * Sets STUN server address.
 * @param {string} addr Domain name of the STUN server. Dotted
 * decimal IP address can be used.
 * @param {number} port Port number of the STUN server. If not
 * defined, default port number 3478 will be used.
 */
Client.prototype.setServerAddr = function (addr, port) {
    var d = addr.split('.');
    if (d.length != 4 || (
        isNaN(parseInt(d[0])) ||
        isNaN(parseInt(d[1])) ||
        isNaN(parseInt(d[2])) ||
        isNaN(parseInt(d[3])))) {
        this._domain = addr;
        this._serv0 = undefined;
    } else {
        this._domain = undefined;
        this._serv0 = addr;
    }

    if (port != undefined) {
        this._port0 = port;
    }
};

/**
 * Starts NAT discovery.
 * @param {object} [option]. Options.
 * @param {boolean} [option.bindingOnly] Perform NAT binding only. Otheriwse
 * perform full NAT discovery process.
 * @param {function} cb Callback made when NAT discovery is complete.
 * The callback function takes an argument, a result code of type {number}
 * defined as stun.Result.
 * @see stun.Result
 * @throws {Error} STUN is already in progress.
 * @throws {Error} STUN server address is not defined yet.
 */
Client.prototype.start = function (option, cb) {
    if (typeof option !== 'object') {
        cb = option;
        option = {};
    }

    // Sanity check
    if (this._state !== State.IDLE)
        throw new Error("Not allowed in state " + this._state);
    if (!this._domain && !this._serv0)
        throw new Error("Address undefined");

    this._cbOnComplete = cb;
    this._mode = (option && option.bindingOnly)? Const.NB_ONLY:Const.Mode.FULL;

    // Initialize.
    this._rtt.init();

    if (!this._serv0) {
        dns.resolve4(this._domain, this._onResolved.bind(this));
        this._state = State.RESOLV;
    } else {
        this._discover();
    }
};

/**
 * Closes STUN client.
 * @param {function} callback Callback made when UDP sockets in use
 * are all closed.
 */
Client.prototype.close = function (callback) {
    this._cbOnClosed = callback;
    if (this._soc0) {
        this._soc0.close();
    }
    if (this._soc1) {
        this._soc1.close();
    }
};

/**
 * Tells whether we are behind a NAT or not.
 * @type boolean
 */
Client.prototype.isNatted = function () {
    return this._isNatted;
};

/**
 * Gets NAT binding type.
 * @type string
 * @see stun.Type
 */
Client.prototype.getNB = function () {
    if (!this.isNatted()) {
        return Const.Type.I;
    }

    if (this._mapped[1].addr && this._mapped[2].addr && this._mapped[3].addr) {
        if (this._mapped[0].port == this._mapped[2].port) {
            if (this._mapped[0].port == this._mapped[1].port) {
                return Const.Type.I;
            }
            return Const.Type.PD;
        }

        if (this._mapped[0].port == this._mapped[1].port) {
            return Const.Type.AD;
        }
        return Const.Type.APD;
    }

    return Const.Type.UNDEF;
};

/**
 * Gets endpoint filter type.
 * @type string
 * @see stun.Type
 */
Client.prototype.getEF = function () {
    if (this.isNatted() == undefined) {
        return Const.Type.UNDEF;
    }

    if (!this.isNatted()) {
        return Const.Type.I;
    }

    if (this._ef.ad == undefined) {
        return Const.Type.UNDEF;
    }

    if (this._ef.pd == undefined) {
        return Const.Type.UNDEF;
    }

    if (this._ef.ad == 0) {
        if (this._ef.pd == 0) {
            return Const.Type.I;
        }
        return Const.Type.PD;
    }

    if (this._ef.pd == 0) {
        return Const.Type.AD;
    }
    return Const.Type.APD;
};

/**
 * Gets name of NAT type.
 * @type string
 */
Client.prototype.getNatType = function () {
    var natted = this.isNatted();
    var nb = this.getNB();
    var ef = this.getEF();

    if (natted == undefined) return "UDP blocked";
    if (!natted) return "Open to internet";
    if (nb == Const.Type.UNDEF || ef == Const.Type.UNDEF)
        return "Natted (details not available)";

    if (nb == Const.Type.I) {
        // Cone.
        if (ef == Const.Type.I) return "Full cone";
        if (ef == Const.Type.PD) return "Port-only-restricted cone";
        if (ef == Const.Type.AD) return "Address-restricted cone";
        return "Port-restricted cone";
    }

    return "Symmetric";
};

/**
 * Gets mapped address (IP address & port) returned by STUN server.
 * @type object
 */
Client.prototype.getMappedAddr = function () {
    return { address:this._mapped[0].addr, port:this._mapped[0].port };
};

/**
 * Gets RTT (Round-Trip Time) in milliseconds measured during
 * NAT binding discovery.
 * @type number
 */
Client.prototype.getRtt = function () { return this._rtt.get(); };


module.exports = Client;
