/*
 * Copyright (c) 2011 Yutaka Takeda <yt0916 at gmail.com>
 * MIT Lincesed
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation 
 * the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the 
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in 
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

var dns = require('dns');
var dgram = require('dgram');
var crypto = require('crypto');

/**
 * @namespace
 * Recommended namespace for stun.js.
 * @name stun
 * @exports exports as stun
 * @example
 * var stun = require('stun');
 */

/**
 * Transport address dependency types.
 * <ul>
 * <li>stun.Type.I: "I" (Independent)</li>
 * <li>stun.Type.PD: "PD" (Port dependent)</li>
 * <li>stun.Type.AD: "AD" (Address dependent)</li>
 * <li>stun.Type.APD: "APD" (Address&Port Dependent)</li>
 * <li>stun.Type.UNDEF: "UNDEF" (Undefined)</li>
 * </ul>
 */
exports.Type = {
    /**
     * Independent. Returns a constant string value of "I".
     */
    get I() { return "I"; },
    /**
     * Port dependent. Returns a constant string value of "PD".
     */
    get PD() { return "PD"; },
    /**
     * Address dependent. Returns a constant string value of "AD".
     */
    get AD() { return "AD"; },
    /**
     * Address and port dependent. Returns a constant string value of "APD".
     */
    get APD() { return "APD" },
    /**
     * Type undefined/undetermined. Returns a constant string value of "UNDEF".
     */
    get UNDEF() { return "UNDEF"; }
}

/**
 * Discovery mode.
 * <ul>
 * <li>stun.Mode.FULL: 0</li>
 * <li>stun.Mode.NB_ONLY: 1</li>
 * </ul>
 */
exports.Mode = {
    /** Performs full NAT type discovery. Returns 0.*/
    get FULL() { return 0; },
    /** NAT binding discovery only. Returns 1. */
    get NB_ONLY() { return 1; }
}

/**
 * Result code.
 * <ul>
 * <li>stun.Result.OK: 0</li>
 * <li>stun.Result.HOST_NOT_FOUND: -1</li>
 * <li>stun.Result.UDP_BLOCKED: -2</li>
 * <li>stun.Result.NB_INCOMPLETE: -3</li>
 * </ul>
 */
exports.Result = {
    /** Successful. */
    get OK() { return 0; },
    /** Domain does not exit. (DNS name resolution failed.) */
    get HOST_NOT_FOUND() { return -1; },
    /** No reply from server. Server may be down. */
    get UDP_BLOCKED() { return -2; },
    /** Partial UDP blockage. NB type discovery was incomplete. */
    get NB_INCOMPLETE() { return -3; }
}

/**
 * StunMessage factory.
 * @type StunMessage
 */
exports.createMessage = function() {
    return new StunMessage();
};

/**
 * StunClient factory.
 * @type StunClient
 */
exports.createClient = function() {
    return new StunClient();
};

/**
 * StunServer factory.
 * @type StunServer
 */
exports.createServer = function() {
    return new StunServer();
};

// Tools.
function inet_aton(a) {
    var d = a.split('.');
    return ((((((+d[0])*256)+(+d[1]))*256)+(+d[2]))*256)+(+d[3]);
}

function inet_ntoa(n) {
    var d = n%256;
    for (var i = 3; i > 0; i--) { 
        n = Math.floor(n/256);
        d = n%256 + '.' + d;
    }
    return d;
}

/** 
 * Constructor for StunMessage object.
 * @class
 * @see stun.createMessage()
 */
function StunMessage() {
    // Message types.
    var _mesgTypes = {
        "breq"  : 0x0001,
        "bres"  : 0x0101,
        "berr"  : 0x0111, // Not supported
        "sreq"  : 0x0002, // Not supported
        "sres"  : 0x0102, // Not supported
        "serr"  : 0x0112, // Not supported
    };

    // Attribute types.
    var _attrTypes = {
        // RFC 3489
        "mappedAddr"    : 0x0001,
        "respAddr"      : 0x0002, // Not supported
        "changeReq"     : 0x0003,
        "sourceAddr"    : 0x0004,
        "changedAddr"   : 0x0005, // Not supported
        "username"      : 0x0006, // Not supported
        "password"      : 0x0007, // Not supported
        "msgIntegrity"  : 0x0008, // Not supported
        "errorCode"     : 0x0009, // Not supported
        "unknownAttr"   : 0x000a, // Not supported
        "reflectedFrom" : 0x000b, // Not supported
        // RFC 3489bis
        "xorMappedAddr" : 0x0020, // Not supported
        // Proprietary.
        "timestamp"     : 0x0032, // <16:srv-delay><16:tx-timestamp>
    };

    var _families = { "ipv4" : 0x01 };

    var _type = _mesgTypes.breq;
    var _tid;
    var _attrs = [];

    var _checkAttrAddr = function(value) {
        if(value["family"] == undefined) {
            value["family"] = "ipv4"
        }
        if(value["port"] == undefined) {
            throw new Error("Port undefined");
        }
        if(value["addr"] == undefined) {
            throw new Error("Addr undefined");
        }
    };

    var _getMesgTypeByVal = function(val) {
        for(type in _mesgTypes) {
            if(_mesgTypes[type] == val) {
                return type;
            }
        }

        throw new Error("Type undefined: " + val);
    }

    var _getAttrTypeByVal = function(val) {
        for(type in _attrTypes) {
            if(_attrTypes[type] == val) {
                return type;
            }
        }

        throw new Error("Unknown attr value: " + val);
    }

    var _readAddr = function(ctx) {
        var family;
        var port;
        var addr;
        ctx.pos++; // skip first byte
        for (f in _families) {
            if(_families[f] == ctx.buf[ctx.pos]) {
                family = f;
                break;
            }
        }
        if(family == undefined) throw new Error("Unsupported family: " + ctx.buf[ctx.pos]);
        ctx.pos++;

        port = ctx.buf[ctx.pos++] << 8;
        port |= ctx.buf[ctx.pos++];

        // Bit operations can handle only 32-bit values.
        // Here needs to use multiplication instead of
        // shift/or operations to avoid inverting signedness.
        addr = ctx.buf[ctx.pos++] * 0x1000000;
        addr += ctx.buf[ctx.pos++] << 16;
        addr += ctx.buf[ctx.pos++] << 8;
        addr += ctx.buf[ctx.pos++];

        return { 'family': family, 'port': port, 'addr': inet_ntoa(addr) };
    };

    var _writeAddr = function(ctx, code, attrVal) {
        if(ctx.buf.length < ctx.pos + 12) throw new Error("Insufficient buffer");

        // Append attribute header.
        ctx.buf[ctx.pos++] = code >> 8;
        ctx.buf[ctx.pos++] = code & 0xff;
        ctx.buf[ctx.pos++] = 0x00;
        ctx.buf[ctx.pos++] = 0x08;

        // Append attribute value.
        ctx.buf[ctx.pos++] = 0x00;
        ctx.buf[ctx.pos++] = _families[attrVal.family];
        ctx.buf[ctx.pos++] = attrVal.port >> 8;
        ctx.buf[ctx.pos++] = attrVal.port & 0xff;

        var addr = inet_aton(attrVal.addr);
        ctx.buf[ctx.pos++] = addr >> 24;
        ctx.buf[ctx.pos++] = (addr >> 16) & 0xff;
        ctx.buf[ctx.pos++] = (addr >> 8) & 0xff;
        ctx.buf[ctx.pos++] = addr & 0xff;
    };

    var _readChangeReq = function(ctx) {
        ctx.pos += 3;
        var chIp = false;
        var chPort = false;
        if(ctx.buf[ctx.pos] & 0x4) { chIp = true; };
        if(ctx.buf[ctx.pos] & 0x2) { chPort = true; };
        ctx.pos++;

        return { 'changeIp': chIp, 'changePort': chPort };
    };

    var _writeChangeReq = function(ctx, attrVal) {
        if(ctx.buf.length < ctx.pos + 8) throw new Error("Insufficient buffer");

        // Append attribute header.
        ctx.buf[ctx.pos++] = _attrTypes.changeReq >> 8;
        ctx.buf[ctx.pos++] = _attrTypes.changeReq & 0xff;
        ctx.buf[ctx.pos++] = 0x00;
        ctx.buf[ctx.pos++] = 0x04;

        // Append attribute value.
        ctx.buf[ctx.pos++] = 0x00;
        ctx.buf[ctx.pos++] = 0x00;
        ctx.buf[ctx.pos++] = 0x00;
        ctx.buf[ctx.pos++] = ((attrVal.changeIp)? 0x4:0x0) | ((attrVal.changePort)? 0x2:0x0)
    };

    var _readTimestamp = function(ctx) {
        var respDelay;
        var timestamp;
        respDelay = ctx.buf[ctx.pos++] << 8
        respDelay |= ctx.buf[ctx.pos++]
        timestamp = ctx.buf[ctx.pos++] << 8
        timestamp |= ctx.buf[ctx.pos++]

        return { 'respDelay': respDelay, 'timestamp': timestamp };
    };

    var _writeTimestamp = function(ctx, attrVal) {
        if(ctx.buf.length < ctx.pos + 8) throw new Error("Insufficient buffer");

        // Append attribute header.
        ctx.buf[ctx.pos++] = _attrTypes.timestamp >> 8;
        ctx.buf[ctx.pos++] = _attrTypes.timestamp & 0xff;
        ctx.buf[ctx.pos++] = 0x00;
        ctx.buf[ctx.pos++] = 0x04;

        // Append attribute value.
        ctx.buf[ctx.pos++] = attrVal.respDelay >> 8;
        ctx.buf[ctx.pos++] = attrVal.respDelay & 0xff;
        ctx.buf[ctx.pos++] = attrVal.timestamp >> 8;
        ctx.buf[ctx.pos++] = attrVal.timestamp & 0xff;
    };

    /**
     * Initializes StunMessage object.
     */
    this.init = function() {
        _type = _mesgTypes.breq;
        _attrs = [];
    };

    /**
     * Sets STUN message type.
     * @param {string} type Message type.
     * @throws {RangeError} Unknown message type.
     */
    this.setType = function(type) {
        _type = _mesgTypes[type];
        if(_type < 0) throw new RangeError("Unknown message type");
    };

    /**
     * Gets STUN message type.
     * @throws {Error} Type undefined.
     * @type string
     */
    this.getType = function() {
        return _getMesgTypeByVal(_type);
    }

    /**
     * Sets transaction ID.
     * @param {string} tid 16-byte transaction ID.
     */
    this.setTransactionId = function(tid) {
        _tid = tid;
    };

    /**
     * Gets transaction ID.
     * @type string
     */
    this.getTransactionId = function() {
        return _tid;
    };

    /**
     * Adds a STUN attribute.
     * @param {string} attrType Attribute type.
     * @param {object} attrVal Attribute value. Structure of this
     * value varies depending on the type.
     * @throws {RangeError} Unknown attribute type.
     * @throws {Error} The 'changeIp' property is undefined.
     * @throws {Error} The 'changePort' property is undefined.
     */
    this.addAttribute = function(attrType, attrVal) {
        var code = _attrTypes[attrType];
        if(code < 0) throw new RangeError("Unknown attribute type");

        // Validate attrVal
        switch(code)
        {
            case 0x0001: // mappedAddr
            case 0x0002: // respAddr
            case 0x0004: // sourceAddr
            case 0x0005: // changedAddr
            case 0x0020: // xorMappedAddr
                _checkAttrAddr(attrVal);
                break;
            case 0x0003: // change-req
                if(attrVal["changeIp"] == undefined) {
                    throw new Error("change IP undefined");
                }
                if(attrVal["changePort"] == undefined) {
                    throw new Error("change Port undefined");
                }
                break;

            case 0x0032: // timestamp
                if(attrVal.respDelay > 0xffff) attrVal.respDealy = 0xffff;
                if(attrVal.timestamp > 0xffff) attrVal.timestamp = 0xffff;
                break;

            case 0x0006: // username
            case 0x0007: // password
            case 0x0008: // msgIntegrity
            case 0x0009: // errorCode
            case 0x000a: // unknownAttr
            case 0x000b: // reflectedFrom
            default:
                throw new Error("Unsupported attribute " + attrType);
        }

        // If the attribute type already exists, replace it with the new one.
        for(var i = 0; i < _attrs.length; ++i) {
            if(_attrs[i].type == attrType) {
                _attrs[i].value = attrVal;
                replaced = true;
                return;
            }
        }

        _attrs.push({type:attrType, value:attrVal});
    };

    /**
     * Gets a list of STUN attributes.
     * @type array
     */
    this.getAttributes = function() {
        return _attrs;
    }

    /**
     * Gets a STUN attributes by its type.
     * @param {string} attrType Attribute type.
     * @type object
     */
    this.getAttribute = function(attrType) {
        for(var i = 0; i < _attrs.length; ++i) {
            if(_attrs[i].type == attrType) {
                return _attrs[i].value;
            }
        }

        return null; // the attribute not found.
    }

    /**
     * Gets byte length a serialized buffer would be.
     * @throws {RangeError}  Unknown attribute type.
     * @type number
     */
    this.getLength = function() {
        var len = 20; // header size (fixed)
        for(var i = 0; i < _attrs.length; ++i) {
            var code = _attrTypes[_attrs[i].type];
            if(code < 0) throw new RangeError("Unknown attribute type");

            // Validate attrVal
            switch(code)
            {
                case 0x0001: // mappedAddr
                case 0x0002: // respAddr
                case 0x0004: // sourceAddr
                case 0x0005: // changedAddr
                case 0x0020: // xorMappedAddr
                    len += 12;
                    break;
                case 0x0003: // changeReq
                    len += 8;
                    break;

                case 0x0032: // timestamp
                    len += 8;
                    break;

                case 0x0006: // username
                case 0x0007: // password
                case 0x0008: // msgIntegrity
                case 0x0009: // errorCode
                case 0x000a: // unknownAttr
                case 0x000b: // reflectedFrom
                default:
                    throw new Error("Unsupported attribute: " + code);
            }
        }

        return len;
    };

    /**
     * Returns a serialized data of type Buffer.
     * @throws {Error} Incorrect transaction ID.
     * @throws {RangeError}  Unknown attribute type.
     * @type buffer
     */
    this.serialize = function() {
        var ctx = {
            buf: new Buffer(this.getLength()),
            pos: 0};

        // Write 'Type'
        ctx.buf[ctx.pos++] = _type >> 8;
        ctx.buf[ctx.pos++] = _type & 0xff;
        // Write 'Length'
        ctx.buf[ctx.pos++] = (ctx.buf.length - 20) >> 8;
        ctx.buf[ctx.pos++] = (ctx.buf.length - 20) & 0xff;
        // Write 'Transaction ID'
        if(_tid == undefined || _tid.length != 16) {
            throw new Error("Incorrect transaction ID");
        }
        for(var i = 0; i < 16; ++i) {
            ctx.buf[ctx.pos++] = _tid.charCodeAt(i);
        }

        for(var i = 0; i < _attrs.length; ++i) {
            var code = _attrTypes[_attrs[i].type];
            if(code < 0) throw new RangeError("Unknown attribute type");

            // Append attribute value
            switch(code) {
                case 0x0001: // mappedAddr
                case 0x0002: // respAddr
                case 0x0004: // sourceAddr
                case 0x0005: // changedAddr
                    _writeAddr(ctx, code, _attrs[i].value);
                    break;
                case 0x0003: // changeReq
                    _writeChangeReq(ctx, _attrs[i].value);
                    break;
                case 0x0032: // timestamp
                    _writeTimestamp(ctx, _attrs[i].value);
                    break;

                case 0x0006: // username
                case 0x0007: // password
                case 0x0008: // msgIntegrity
                case 0x0009: // errorCode
                case 0x000a: // unknownAttr
                case 0x000b: // reflectedFrom
                default:
                    throw new Error("Unsupported attribute");
            }
        }

        return ctx.buf;
    };

    /**
     * Deserializes a serialized data into this object.
     * @param {buffer} buffer Data to be deserialized.
     * @throws {Error} Malformed data in the buffer.
     */
    this.deserialize = function(buffer) {
        var ctx = {
            pos:0,
            buf:buffer
        };

        // Initialize.
        _type = 0;
        _tid = undefined;
        _attrs = [];

        // buffer must be >= 20 bytes.
        if(ctx.buf.length < 20)
            throw new Error("Malformed data");

        // Parse type.
        _type = ctx.buf[ctx.pos++] << 8;
        _type |= ctx.buf[ctx.pos++];

        // Parse length
        var len;
        len = ctx.buf[ctx.pos++] << 8;
        len |= ctx.buf[ctx.pos++];

        // Parse tid.
        _tid = ctx.buf.toString('binary', ctx.pos, ctx.pos + 16);
        ctx.pos += 16;

        // The remaining length should match the value in the length field.
        if(ctx.buf.length - 20 != len)
            throw new Error("Malformed data");

        while(ctx.pos < ctx.buf.length) {
            // Remaining size in the buffer must be >= 4.
            if(ctx.buf.length - ctx.pos < 4)
                throw new Error("Malformed data");

            var attrLen;
            var code;

            code = ctx.buf[ctx.pos++] << 8;
            code |= ctx.buf[ctx.pos++];
            attrLen = ctx.buf[ctx.pos++] << 8;
            attrLen |= ctx.buf[ctx.pos++];

            // Remaining size must be >= attrLen.
            if(ctx.buf.length - ctx.pos < attrLen)
                throw new Error("Malformed data: code=" + code + " rem=" + (ctx.buf.length - ctx.pos) + " len=" + attrLen);


            var attrVal;

            switch(code) {
                case 0x0001: // mappedAddAr
                case 0x0002: // respAddr
                case 0x0004: // sourceAddr
                case 0x0005: // changedAddr
                    if(attrLen != 8) throw new Error("Malformed data");
                    attrVal = _readAddr(ctx);
                    break;
                case 0x0003: // changeReq
                    if(attrLen != 4) throw new Error("Malformed data");
                    attrVal = _readChangeReq(ctx);
                    break;
                case 0x0032: // xorMappedAddr
                    if(attrLen != 4) throw new Error("Malformed data");
                    attrVal = _readTimestamp(ctx);
                    break;
                case 0x0006: // username
                case 0x0007: // password
                case 0x0008: // msgIntegrity
                case 0x0009: // errorCode
                case 0x000a: // unknownAttr
                case 0x000b: // reflectedFrom
                default:
                    // We do not know of this type.
                    // Skip this attribute.
                    ctx.pos += attrLen;
                    continue;
            }

            _attrs.push({type:_getAttrTypeByVal(code), value:attrVal});
        }
    };
}

/////////////////////////////////////////////////////////////////////

/** 
 * Constructor for StunClient object.
 * @class
 * @see stun.createClient()
 */
function StunClient() {
    var _State = {
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
    };

    // Private: 
    var _domain; // FQDN
    var _serv0; // Dotted decimal.
    var _serv1; // Dotted decimal.
    var _port0 = 3478;
    var _port1; // Obtained via CHANGE-ADDRESS
    var _local = { addr:'0.0.0.0', port:0 };
    var _soc0;
    var _soc1;
    var _breq0; // Binding request 0 of type StunMessage.
    var _breq1; // Binding request 1 of type StunMessage.
    var _state = _State.IDLE;
    var _mapped = [
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
    var _ef = { ad: undefined, pd: undefined };
    var _numSocs = 0;
    var _cbOnComplete;
    var _cbOnClosed;
    var _intervalId;
    var _retrans = 0; // num of retransmissions
    var _elapsed = 0; // *100 msec
    var _mode = exports.Mode.FULL;
    var _now = function() { return (new Date()).getTime(); };
    var _rtt = new function () {
        var _sum = 0;
        var _num = 0;
        this.init = function() { _sum = 0; _num = 0; };
        this.addSample = function(rtt) { _sum += rtt; _num++; };
        this.get = function() { return _num?(_sum/_num):0; };
    };
    
    var _isLocalAddr = function(addr) {
        var dummy = dgram.createSocket('udp4');
        try {
            dummy.bind(0, addr);
        }
        catch(e) {
            if(e.code == 'EADDRNOTAVAIL') {
                dummy.close();
                return false;
            }
            throw e;
        }

        dummy.close();
        return true;
    }

    var _discover = function() {
        // Create socket 0.
        _soc0 = dgram.createSocket("udp4");
        _soc0.on("listening", function () {
                _onListening();
                });
        _soc0.on("message", function (msg, rinfo) {
                _onReceived(msg, rinfo);
                });
        _soc0.on("close", function () {
                _onClosed();
                });

        // Start listening on the local port.
        _soc0.bind(0, _local.addr);

        // Get assigned port name for this socket.
        _local.addr = _soc0.address().address;
        _local.port = _soc0.address().port;

        _breq0 = new StunMessage();
        _breq0.init();
        _breq0.setType('breq');
        _breq0.setTransactionId(_randTransId());
        _breq0.addAttribute(
                'timestamp', {
                    'respDelay': 0, 
                    'timestamp': (_now() & 0xffff)});

        var msg = _breq0.serialize();
        _soc0.send(msg, 0, msg.length, _port0, _serv0);

        _retrans = 0;
        _elapsed = 0;
        _intervalId = setInterval(_onTick, 100);
        _state = _State.NBDaDp;
    }

    var _onResolved = function(err, addresses) {
        if(err) {
            console.log(err);
            if(_cbOnComplete != undefined) {
                _cbOnComplete(exports.Result.HOST_NOT_FOUND);
            }
            return;
        }

        _serv0 = addresses[0];
        _discover();
    }

    var _onListening = function() {
        _numSocs++;
        //console.log("_numSocs++: " + _numSocs);
    };

    var _onClosed = function() {
        if(_numSocs > 0) {
            _numSocs--;
            //console.log("_numSocs--: " + _numSocs);
            if(_cbOnClosed != undefined && !_numSocs) {
                _cbOnClosed();
            }
        }
    };

    var _onTick = function() {
        // _retrans _elapsed
        //    0       1( 1)  == Math.min((1 << _retrans), 16)
        //    1       2( 3)
        //    2       4( 7)
        //    3       8(15)
        //    4      16(31)
        //    5      16(47)
        //    6      16(63)
        //    7      16(79)
        //    8      16(95)

        _elapsed++;

        if(_elapsed >= Math.min((1 << _retrans), 16)) {
            // Retransmission timeout.
            _retrans++;
            _elapsed = 0;

            if( _state == _State.NBDaDp ||
                _state == _State.NBDaCp ||
                _state == _State.NBCaDp ||
                _state == _State.NBCaCp) {
                if(_retrans < 9) {
                    _breq0.addAttribute(
                            'timestamp', {
                                'respDelay': 0, 
                                'timestamp': (_now() & 0xffff)});
                    var sbuf = _breq0.serialize();
                    var toAddr;
                    var toPort;

                    switch(_state) {
                        case _State.NBDaDp:
                            toAddr = _serv0; toPort = _port0;
                            break;
                        case _State.NBDaCp:
                            toAddr = _serv0; toPort = _port1;
                            break;
                        case _State.NBCaDp:
                            toAddr = _serv1; toPort = _port0;
                            break;
                        case _State.NBCaCp:
                            toAddr = _serv1; toPort = _port1;
                            break;
                    }

                    _soc0.send(sbuf, 0, sbuf.length, toPort, toAddr);
                    console.log("NB-Rtx0: len=" + sbuf.length + " retrans=" + _retrans + " elapsed=" + _elapsed + " to=" + toAddr + ":" + toPort);
                }
                else {
                    clearInterval(_intervalId);
                    var firstNB = (_state == _State.NBDaDp);
                    _state = _State.COMPLETE;

                    if(_cbOnComplete != undefined) {
                        if(firstNB) {
                            _cbOnComplete(exports.Result.UDP_BLOCKED);
                        }
                        else {
                            // First binding succeeded, then subsequent
                            // binding should work, but didn't.
                            _cbOnComplete(exports.Result.NB_INCOMPLETE);
                        }
                    }
                }
            }
            else if(_state == _State.EFDiscov) {
                if(_ef.ad == undefined) {
                    if(_retrans < 9) {
                        var sbuf = _breq0.serialize();
                        _soc1.send(sbuf, 0, sbuf.length, _port0, _serv0);
                        console.log("EF-Rtx0: retrans=" + _retrans + " elapsed=" + _elapsed);
                    }
                    else {
                        _ef.ad = 1;
                    }
                }
                if(_ef.pd == undefined) {
                    if(_retrans < 9) {
                        var sbuf = _breq1.serialize();
                        _soc1.send(sbuf, 0, sbuf.length, _port0, _serv0);
                        console.log("EF-Rtx1: retrans=" + _retrans + " elapsed=" + _elapsed);
                    }
                    else {
                        _ef.pd = 1;
                    }
                }
                if(_ef.ad != undefined && _ef.pd != undefined) {
                    clearInterval(_intervalId);
                    _state = _State.COMPLETE;
                    if(_cbOnComplete != undefined) {
                        _cbOnComplete(exports.Result.OK);
                    }
                }
            }
            else {
                console.log("Warning: unexpected timer event. Forgot to clear timer?");
                clearInterval(_intervalId);
            }
        }
    }

    var _onReceived = function(msg, rinfo) {
        var bres = new StunMessage();
        var val;

        try {
            bres.deserialize(msg);
        }
        catch(e) {
            _stats.numMalformed++;
            console.log("Error: " + e.message);
            return;
        }

        // We are only interested in binding response.
        if(bres.getType() != 'bres') {
            return;
        }

        if(_state == _State.NBDaDp) {
            if(bres.getTransactionId() != _breq0.getTransactionId()) {
                return; // discard
            }

            clearInterval(_intervalId);

            // Get MAPPED-ADDRESS value.
            val = bres.getAttribute('mappedAddr');
            if(val == undefined) {
                console.log("Error: MAPPED-ADDRESS not present");
                return;
            }
            _mapped[0].addr = val.addr;
            _mapped[0].port = val.port;

            // Get CHANGED-ADDRESS value.
            val = bres.getAttribute('changedAddr');
            if(val == undefined) {
                console.log("Error: MAPPED-ADDRESS not present");
                return;
            }
            _serv1 = val.addr;
            _port1 = val.port;

            // Calculate RTT if timestamp is attached.
            val = bres.getAttribute('timestamp');
            if(val != undefined) {
                _rtt.addSample(((_now() & 0xffff) - val.timestamp) - val.respDelay);
            }

            console.log("MAPPED0: addr=" + _mapped[0].addr + ":" + _mapped[0].port);
            //console.log("CHANGED: addr=" + _serv1 + ":" + _port1);

            // Start NBDaCp.
            _breq0.init();
            _breq0.setType('breq');
            _breq0.setTransactionId(_randTransId());
            _breq0.addAttribute(
                    'timestamp', {
                        'respDelay': 0, 
                        'timestamp': (_now() & 0xffff)});
            var sbuf = _breq0.serialize();
            _soc0.send(sbuf, 0, sbuf.length, _port1, _serv0);

            _retrans = 0;
            _elapsed = 0;
            _intervalId = setInterval(_onTick, 100);
            _state = _State.NBDaCp;
        }
        else if(_state == _State.NBDaCp) {
            if(bres.getTransactionId() != _breq0.getTransactionId()) {
                return; // discard
            }

            clearInterval(_intervalId);

            // Get MAPPED-ADDRESS value.
            val = bres.getAttribute('mappedAddr');
            if(val == undefined) {
                console.log("Error: MAPPED-ADDRESS not present");
                return;
            }
            _mapped[1].addr = val.addr;
            _mapped[1].port = val.port;

            // Calculate RTT if timestamp is attached.
            val = bres.getAttribute('timestamp');
            if(val != undefined) {
                _rtt.addSample(((_now() & 0xffff) - val.timestamp) - val.respDelay);
            }

            console.log("MAPPED1: addr=" + _mapped[1].addr + ":" + _mapped[1].port);

            // Start NBCaDp.
            _breq0.init();
            _breq0.setType('breq');
            _breq0.setTransactionId(_randTransId());
            _breq0.addAttribute(
                    'timestamp', {
                        'respDelay': 0, 
                        'timestamp': (_now() & 0xffff)});
            var sbuf = _breq0.serialize();
            _soc0.send(sbuf, 0, sbuf.length, _port0, _serv1);

            _retrans = 0;
            _elapsed = 0;
            _intervalId = setInterval(_onTick, 100);
            _state = _State.NBCaDp;
        }
        else if(_state == _State.NBCaDp) {
            if(bres.getTransactionId() != _breq0.getTransactionId()) {
                return; // discard
            }

            clearInterval(_intervalId);

            // Get MAPPED-ADDRESS value.
            val = bres.getAttribute('mappedAddr');
            if(val == undefined) {
                console.log("Error: MAPPED-ADDRESS not present");
                return;
            }
            _mapped[2].addr = val.addr;
            _mapped[2].port = val.port;

            // Calculate RTT if timestamp is attached.
            val = bres.getAttribute('timestamp');
            if(val != undefined) {
                _rtt.addSample(((_now() & 0xffff) - val.timestamp) - val.respDelay);
            }

            console.log("MAPPED2: addr=" + _mapped[2].addr + ":" + _mapped[2].port);

            // Start NBCaCp.
            _breq0.init();
            _breq0.setType('breq');
            _breq0.setTransactionId(_randTransId());
            _breq0.addAttribute(
                    'timestamp', {
                        'respDelay': 0, 
                        'timestamp': (_now() & 0xffff)});
            var sbuf = _breq0.serialize();
            _soc0.send(sbuf, 0, sbuf.length, _port1, _serv1);

            _retrans = 0;
            _elapsed = 0;
            _intervalId = setInterval(_onTick, 100);
            _state = _State.NBCaCp;
        }
        else if(_state == _State.NBCaCp) {
            if(bres.getTransactionId() != _breq0.getTransactionId()) {
                return; // discard
            }

            clearInterval(_intervalId);

            // Get MAPPED-ADDRESS value.
            val = bres.getAttribute('mappedAddr');
            if(val == undefined) {
                console.log("Error: MAPPED-ADDRESS not present");
                return;
            }
            _mapped[3].addr = val.addr;
            _mapped[3].port = val.port;

            // Calculate RTT if timestamp is attached.
            val = bres.getAttribute('timestamp');
            if(val != undefined) {
                _rtt.addSample(((_now() & 0xffff) - val.timestamp) - val.respDelay);
            }

            console.log("MAPPED3: addr=" + _mapped[3].addr + ":" + _mapped[3].port);

            // Start NBDiscov.
            _ef.ad = undefined;
            _ef.pd = undefined;

            // Create another socket (_soc1) from which EFDiscov is performed).
            _soc1 = dgram.createSocket("udp4");
            _soc1.on("listening", function () {
                    _onListening();
                    });
            _soc1.on("message", function (msg, rinfo) {
                    _onReceived(msg, rinfo);
                    });
            _soc1.on("close", function () {
                    _onClosed();
                    });

            // Start listening on the local port.
            _soc1.bind(0, _local.addr);

            // changeIp=true,changePort=true from _soc1
            var sbuf
            _breq0.init();
            _breq0.setType('breq');
            _breq0.setTransactionId(_randTransId());
            _breq0.addAttribute(
                    'changeReq', {
                        'changeIp': true, 
                        'changePort': true});

            sbuf = _breq0.serialize();
            _soc1.send(sbuf, 0, sbuf.length, _port0, _serv0);

            // changeIp=false,changePort=true from _soc1
            _breq1 = new StunMessage();
            _breq1.setType('breq');
            _breq1.setTransactionId(_randTransId());
            _breq1.addAttribute(
                    'changeReq', {
                        'changeIp': false, 
                        'changePort': true});

            sbuf = _breq1.serialize();
            _soc1.send(sbuf, 0, sbuf.length, _port0, _serv0);

            _retrans = 0;
            _elapsed = 0;
            _intervalId = setInterval(_onTick, 100);
            _state = _State.EFDiscov;
        }
        else if(_state == _State.EFDiscov) {
            var res = -1;
            if(_ef.ad == undefined) {
                if(bres.getTransactionId() == _breq0.getTransactionId()) {
                    res = 0;
                }
            }
            if(res < 0 && _ef.pd == undefined) {
                if(bres.getTransactionId() == _breq1.getTransactionId()) {
                    res = 1;
                }
            }

            if(res < 0) return; // discard

            if(res == 0) { _ef.ad = 0; }
            else { _ef.pd = 0; }

            if(_ef.ad != undefined && _ef.pd != undefined) {
                clearInterval(_intervalId);
                _state = _State.COMPLETE;
                if(_cbOnComplete != undefined) {
                    _cbOnComplete(exports.Result.OK);
                }
            }
        }
        else {
            return; // discard
        }

    };

    var _randTransId = function() {
        var seed = process.pid.toString(16);
        seed += Math.round(Math.random() * 0x100000000).toString(16);
        seed += (new Date()).getTime().toString(16);
        var md5 = crypto.createHash('md5');
        md5.update(seed);
        return md5.digest();
    }

    // Public: 

    /**
     * Sets local address. Use of this method is optional. If your 
     * local device has more then one interfaces, you can specify
     * one of these interfaces form which STUN is performed.
     * @param {string} addr Local IP address.
     * @throws {Error} The address not available.
     */
    this.setLocalAddr = function(addr) {
        if(!_isLocalAddr(addr)) {
            throw new Error("Addr not available");
        }

        _local.addr = addr;
        _local.port = 0;
    };

    /**
     * Sets STUN server address.
     * @param {string} addr Domain name of the STUN server. Dotted
     * decimal IP address can be used.
     * @param {number} port Port number of the STUN server. If not
     * defined, default port number 3478 will be used.
     */
    this.setServerAddr = function(addr, port) {
        var d = addr.split('.');
        if(d.length != 4 || (
                    parseInt(d[0]) == NaN ||
                    parseInt(d[1]) == NaN ||
                    parseInt(d[2]) == NaN ||
                    parseInt(d[3]) == NaN))
        {
            _domain = addr;
            _serv0 = undefined;
        }
        else {
            _domain = undefined;
            _serv0 = addr;
        }

        if(port != undefined) { _port = port; }
    };

    /**
     * Starts NAT discovery.
     * @param {function} callback Callback made when NAT discovery is complete.
     * The callback function takes an argument - a result code of type {number}
     * defined as stun.Result.
     * @see stun.Result
     * @param {number} Mode. (Not implemented. May leave it undefined)
     * @throws {Error} STUN is already in progress.
     * @throws {Error} STUN server address is not defined yet.
     */
    this.start = function(callback, mode) {
        // Sanity check
        if(_state !== _State.IDLE)
            throw new Error("Not allowed in state " + _state);
        if(_domain == undefined && _serv0 == undefined)
            throw new Error("Address undefined");

        _cbOnComplete = callback;
        _mode = (mode == undefined)? exports.Mode.FULL:mode;

        // Initialize.
        _rtt.init();

        if(_serv0 == undefined) {
            dns.resolve4(_domain, _onResolved);
            _state = _State.RESOLV;
        }
        else { _discover(); }
    };

    /**
     * Closes STUN client.
     * @param {function} callback Callback made when UDP sockets in use
     * are all closed.
     */
    this.close = function(callback) {
        _cbOnClosed = callback;
        if(_soc0 != undefined) {
            var sin = _soc0.address();
            _soc0.close();
        }
        if(_soc1 != undefined) {
            var sin = _soc1.address();
            _soc1.close();
        }
    };

    /**
     * Tells whether we are behind a NAT or not.
     * @type boolean
     */
    this.isNatted = function() {
        if(_local.addr == '0.0.0.0') {
            return !_isLocalAddr(_mapped[0].addr);
        }

        return (_mapped[0].addr)? (_mapped[0].addr != _local.addr):undefined;
    }

    /**
     * Gets NAT binding type.
     * @type string
     * @see stun.Type
     */
    this.getNB = function() {
        if(!this.isNatted()) {
            return exports.Type.I;
        }

        if(_mapped[1].addr && _mapped[2].addr && _mapped[3].addr) {
            if(_mapped[0].port == _mapped[2].port) {
                if(_mapped[0].port == _mapped[1].port) {
                    return exports.Type.I;
                }
                return exports.Type.PD;
            }

            if(_mapped[0].port == _mapped[1].port) {
                return exports.Type.AD;
            }
            return exports.Type.APD;
        }

        return exports.Type.UNDEF;
    };

    /**
     * Gets endpoint filter type.
     * @type string
     * @see stun.Type
     */
    this.getEF = function() {
        if(this.isNatted() == undefined) {
            return exports.Type.UNDEF;
        }

        if(!this.isNatted()) {
            return exports.Type.I;
        }

        if(_ef.ad == undefined) {
			console.log("_ef.ad was undefined");
            return exports.Type.UNDEF;
        }

        if(_ef.pd == undefined) {
			console.log("_ef.pd was undefined");
            return exports.Type.UNDEF;
        }

        if(_ef.ad == 0) {
            if(_ef.pd == 0) {
                return exports.Type.I;
            }
            return exports.Type.PD;
        }

        if(_ef.pd == 0) {
            return exports.Type.AD;
        }
        return exports.Type.APD;
    };

    /**
     * Gets name of NAT type.
     * @type string
     */
    this.getNatType = function() {
        var natted = this.isNatted();
        var nb = this.getNB();
        var ef = this.getEF();

        if(natted == undefined) return "UDP blocked";
        if(!natted) return "Open to internet";
        if(nb == exports.Type.UNDEF || ef == exports.Type.UNDEF)
            return "Natted (details not available)";

        if(nb == exports.Type.I) {
            // Cone.
            if(ef == exports.Type.I) return "Full cone";
            if(ef == exports.Type.PD) return "Port-only-restricted cone";
            if(ef == exports.Type.AD) return "Address-restricted cone";
            return "Port-restricted cone";
        }

        return "Symmetric";
    }

    /**
     * Gets mapped address (IP address & port) returned by STUN server.
     * @type object
     */
    this.getMappedAddr = function() {
        return { address:_mapped[0].addr, port:_mapped[0].port };
    };

    /**
     * Gets RTT (Round-Trip Time) in milliseconds measured during
     * NAT binding discovery.
     * @type number
     */
    this.getRtt = function() { return _rtt.get(); };
}

/////////////////////////////////////////////////////////////////////

/** 
 * Constructor for StunServer object.
 * To instantiate a StunServer object, use createServer() function.
 * @class
 * @see stun.createServer()
 */
function StunServer() {
    // Private: 
    var _addr0;
    var _addr1;
    var _port0 = 3478;
    var _port1 = 3479;
    var _sockets = [];
    var _stats = {
        numRcvd: 0,
        numSent: 0,
        numMalformed: 0,
        numUnsupported: 0,
    };

    var _now = function() { return (new Date()).getTime(); };

    var _onListening = function(sid) {
        var sin = _sockets[sid].address();
        console.log("soc[" + sid + "] listening on " + sin.address + ":" + sin.port);
    };

    var _onReceived = function(sid, msg, rinfo) {
        console.log("soc[" + sid + "] received from " + rinfo.address + ":" + rinfo.port);

        var stunmsg = new StunMessage();
        var fid = sid; // source socket ID for response

        _stats.numRcvd++;

        try {
            stunmsg.deserialize(msg);
        }
        catch(e) {
            _stats.numMalformed++;
            console.log("Error: " + e.message);
            return;
        }

        // We are only interested in binding request.
        if(stunmsg.getType() != 'breq') {
            _stats.numUnsupported++;
            return;
        }

        var val;

        // Modify source socket ID (fid) based on 
        // CHANGE-REQUEST attribute.
        val = stunmsg.getAttribute('changeReq');
        if(val != undefined) {
            if(val.changeIp) {
                fid ^= 0x2;
            }
            if(val.changePort) {
                fid ^= 0x1;
            }
        }

        // Check if it has timestamp attribute.
        var txTs;
        var rcvdAt = _now();
        val = stunmsg.getAttribute('timestamp');
        if(val != undefined) {
            txTs = val.timestamp;
        }

        //console.log("sid=" + sid + " fid=" + fid);

        try {
            // Initialize the message object to reuse.
            // The init() does not reset transaction ID.
            stunmsg.init();
            stunmsg.setType('bres');

            // Add mapped address.
            stunmsg.addAttribute(
                    'mappedAddr', {
                        'family': 'ipv4', 
                        'port': rinfo.port,
                        'addr': rinfo.address});

            // Offer CHANGED-ADDRESS only when _addr1 is defined.
            if(_addr1 != undefined) {
                var chAddr = (sid & 0x2)?_addr0:_addr1;
                var chPort = (sid & 0x1)?_port0:_port1;

                stunmsg.addAttribute(
                    'changedAddr', {
                        'family': 'ipv4', 
                        'port': chPort,
                        'addr': chAddr});
            }

            var soc = _sockets[fid];

            // Add source address.
            stunmsg.addAttribute(
                    'sourceAddr', {
                        'family': 'ipv4', 
                        'port': soc.address().port,
                        'addr': soc.address().address});

            // Add timestamp if existed in the request.
            if(txTs != undefined) {
                stunmsg.addAttribute(
                    'timestamp', {
                        'respDelay': ((_now() - rcvdAt) & 0xffff), 
                        'timestamp': txTs});
            }

            var resp = stunmsg.serialize();
            if(soc == undefined) throw new Error("Invalid from ID: " + fid);
            console.log('soc[' + fid + '] sending ' + resp.length + ' bytes');
            soc.send(   resp,
                        0,
                        resp.length,
                        rinfo.port,
                        rinfo.address);
        }
        catch(e) {
            _stats.numMalformed++;
            console.log("Error: " + e.message);
        }

        _stats.numSent++;
    };

    var _getPort = function(sid) {
        return (sid & 1)?_port1:_port0;
    };

    var _getAddr = function(sid) {
        return (sid & 2)?_addr1:_addr0;
    };

    // Public: 

    /**
     * Sets primary server address.
     * @param {string} addr0 Dotted decimal IP address.
     */
    this.setAddress0 = function(addr0) {
        _addr0 = addr0;
    };

    /**
     * Sets secondary server address.
     * @param {string} addr1 Dotted decimal IP address.
     */
    this.setAddress1 = function(addr1) {
        _addr1 = addr1;
    };

    /**
     * Starts listening to STUN requests from clients.
     * @throws {Error} Server address undefined.
     */
    this.listen = function() {
        // Sanity check
        if(_addr0 == undefined) throw new Error("Address undefined");
        if(_addr1 == undefined) throw new Error("Address undefined");

        for(var i = 0; i < 4; ++i) {
            // Create socket and add it to socket array.
            var soc = dgram.createSocket("udp4");
            _sockets.push(soc);

            switch(i) {
                case 0:
                    soc.on("listening", function () { _onListening(0); });
                    soc.on("message", function (msg, rinfo) { _onReceived(0, msg, rinfo); });
                    break;
                case 1:
                    soc.on("listening", function () { _onListening(1); });
                    soc.on("message", function (msg, rinfo) { _onReceived(1, msg, rinfo); });
                    break;
                case 2:
                    soc.on("listening", function () { _onListening(2); });
                    soc.on("message", function (msg, rinfo) { _onReceived(2, msg, rinfo); });
                    break;
                case 3:
                    soc.on("listening", function () { _onListening(3); });
                    soc.on("message", function (msg, rinfo) { _onReceived(3, msg, rinfo); });
                    break;
                default:
                    throw new RangeError("Out of socket array");
            }

            // Start listening.
            soc.bind(_getPort(i), _getAddr(i));
        }
    };

    /**
     * Closes the STUN server.
     */
    this.close = function() {
        while(_sockets.length > 0) {
            var soc = _sockets.shift();
            var sin = soc.address();
            console.log("Closing socket on " + sin.address + ":" + sin.port);
            soc.close();
        }
    };
}

