'use strict';

var Utils = require('./utils');
var Const = require('./const');

/**
 * Constructor for StunMessage object.
 * @class
 * @see stun.createMessage()
 */
function Message() {
    this._type = Const.MesgTypes.breq;
    this._tid;
    this._attrs = [];
}

/**
 * @private
 * @static
 */
Message._checkAttrAddr = function (value) {
    if (value["family"] == undefined) {
        value["family"] = "ipv4";
    }
    if (value["port"] == undefined) {
        throw new Error("Port undefined");
    }
    if (value["addr"] == undefined) {
        throw new Error("Addr undefined");
    }
};

/**
 * @private
 * @static
 */
Message._getMesgTypeByVal = function (val) {
    var types = Object.keys(Const.MesgTypes);
    for (var i = 0; i < types.length; ++i) {
        if (Const.MesgTypes[types[i]] == val) {
            return types[i];
        }
    }

    throw new Error("Type undefined: " + val);
};

/**
 * @private
 * @static
 */
Message._getAttrTypeByVal = function (val) {
    var types = Object.keys(Const.AttrTypes);
    for (var i = 0; i < types.length; ++i) {
        if (Const.AttrTypes[types[i]] == val) {
            return types[i];
        }
    }

    throw new Error("Unknown attr value: " + val);
};

/**
 * @private
 * @static
 */
Message._readAddr = function (ctx) {
    var family;
    var port;
    var addr;
    ctx.pos++; // skip first byte
    var families = Object.keys(Const.Families);
    for (var i = 0; i < families.length; ++i) {
        if (Const.Families[families[i]] === ctx.buf[ctx.pos]) {
            family = families[i];
            break;
        }
    }
    if (family == undefined) throw new Error("Unsupported family: " + ctx.buf[ctx.pos]);
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

    return { 'family': family, 'port': port, 'addr': Utils.inetNtoa(addr) };
};

/**
 * @private
 * @static
 */
Message._writeAddr = function (ctx, code, attrVal) {
    if (ctx.buf.length < ctx.pos + 12) {
        throw new Error("Insufficient buffer");
    }

    // Append attribute header.
    ctx.buf[ctx.pos++] = code >> 8;
    ctx.buf[ctx.pos++] = code & 0xff;
    ctx.buf[ctx.pos++] = 0x00;
    ctx.buf[ctx.pos++] = 0x08;

    // Append attribute value.
    ctx.buf[ctx.pos++] = 0x00;
    ctx.buf[ctx.pos++] = Const.Families[attrVal.family];
    ctx.buf[ctx.pos++] = attrVal.port >> 8;
    ctx.buf[ctx.pos++] = attrVal.port & 0xff;

    var addr = Utils.inetAton(attrVal.addr);
    ctx.buf[ctx.pos++] = addr >> 24;
    ctx.buf[ctx.pos++] = (addr >> 16) & 0xff;
    ctx.buf[ctx.pos++] = (addr >> 8) & 0xff;
    ctx.buf[ctx.pos++] = addr & 0xff;
};

/**
 * @private
 * @static
 */
Message._readChangeReq = function (ctx) {
    ctx.pos += 3;
    var chIp = false;
    var chPort = false;
    if (ctx.buf[ctx.pos] & 0x4) { chIp = true; }
    if (ctx.buf[ctx.pos] & 0x2) { chPort = true; }
    ctx.pos++;

    return { 'changeIp': chIp, 'changePort': chPort };
};

/**
 * @private
 * @static
 */
Message._writeChangeReq = function (ctx, attrVal) {
    if (ctx.buf.length < ctx.pos + 8) {
        throw new Error("Insufficient buffer");
    }

    // Append attribute header.
    ctx.buf[ctx.pos++] = Const.AttrTypes.changeReq >> 8;
    ctx.buf[ctx.pos++] = Const.AttrTypes.changeReq & 0xff;
    ctx.buf[ctx.pos++] = 0x00;
    ctx.buf[ctx.pos++] = 0x04;

    // Append attribute value.
    ctx.buf[ctx.pos++] = 0x00;
    ctx.buf[ctx.pos++] = 0x00;
    ctx.buf[ctx.pos++] = 0x00;
    ctx.buf[ctx.pos++] = ((attrVal.changeIp)? 0x4:0x0) | ((attrVal.changePort)? 0x2:0x0);
};

/**
 * @private
 * @static
 */
Message._readTimestamp = function (ctx) {
    var respDelay;
    var timestamp;
    respDelay = ctx.buf[ctx.pos++] << 8;
    respDelay |= ctx.buf[ctx.pos++];
    timestamp = ctx.buf[ctx.pos++] << 8;
    timestamp |= ctx.buf[ctx.pos++];

    return { 'respDelay': respDelay, 'timestamp': timestamp };
};

/**
 * @private
 * @static
 */
Message._writeTimestamp = function (ctx, attrVal) {
    if (ctx.buf.length < ctx.pos + 8) {
        throw new Error("Insufficient buffer");
    }

    // Append attribute header.
    ctx.buf[ctx.pos++] = Const.AttrTypes.timestamp >> 8;
    ctx.buf[ctx.pos++] = Const.AttrTypes.timestamp & 0xff;
    ctx.buf[ctx.pos++] = 0x00;
    ctx.buf[ctx.pos++] = 0x04;

    // Append attribute value.
    ctx.buf[ctx.pos++] = attrVal.respDelay >> 8;
    ctx.buf[ctx.pos++] = attrVal.respDelay & 0xff;
    ctx.buf[ctx.pos++] = attrVal.timestamp >> 8;
    ctx.buf[ctx.pos++] = attrVal.timestamp & 0xff;
};

/**
 * Initializes Message object.
 */
Message.prototype.init = function () {
    this._type = Const.MesgTypes.breq;
    this._attrs = [];
};

/**
 * Sets STUN message type.
 * @param {string} type Message type.
 * @throws {RangeError} Unknown message type.
 */
Message.prototype.setType = function (type) {
    this._type = Const.MesgTypes[type];
    if (this._type < 0) throw new RangeError("Unknown message type");
};

/**
 * Gets STUN message type.
 * @throws {Error} Type undefined.
 * @type string
 */
Message.prototype.getType = function () {
    var Ctor = this.constructor;
    return Ctor._getMesgTypeByVal(this._type);
};

/**
 * Sets transaction ID.
 * @param {Buffer} tid 16-byte transaction ID.
 */
Message.prototype.setTransactionId = function (tid) {
    this._tid = tid;
};

/**
 * Gets transaction ID.
 * @returns {Buffer} 16-byte Transaction ID.
 */
Message.prototype.getTransactionId = function () {
    return this._tid;
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
Message.prototype.addAttribute = function (attrType, attrVal) {
    var Ctor = this.constructor;
    var code = Const.AttrTypes[attrType];
    if (code < 0) {
        throw new RangeError("Unknown attribute type");
    }

    // Validate attrVal
    switch (code) {
        case 0x0001: // mappedAddr
        case 0x0002: // respAddr
        case 0x0004: // sourceAddr
        case 0x0005: // changedAddr
        case 0x0020: // xorMappedAddr
            Ctor._checkAttrAddr(attrVal);
            break;
        case 0x0003: // change-req
            if (attrVal["changeIp"] == undefined) {
                throw new Error("change IP undefined");
            }
            if (attrVal["changePort"] == undefined) {
                throw new Error("change Port undefined");
            }
            break;

        case 0x0032: // timestamp
            if (attrVal.respDelay > 0xffff) {
                attrVal.respDealy = 0xffff;
            }
            if (attrVal.timestamp > 0xffff) {
                attrVal.timestamp = 0xffff;
            }
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
    for (var i = 0; i < this._attrs.length; ++i) {
        if (this._attrs[i].type == attrType) {
            this._attrs[i].value = attrVal;
            return;
        }
    }

    this._attrs.push({type:attrType, value:attrVal});
};

/**
 * Gets a list of STUN attributes.
 * @type array
 */
Message.prototype.getAttributes = function () {
    return this._attrs;
};

/**
 * Gets a STUN attributes by its type.
 * @param {string} attrType Attribute type.
 * @type object
 */
Message.prototype.getAttribute = function (attrType) {
    for (var i = 0; i < this._attrs.length; ++i) {
        if (this._attrs[i].type === attrType) {
            return this._attrs[i].value;
        }
    }

    return null; // the attribute not found.
};

/**
 * Gets byte length a serialized buffer would be.
 * @throws {RangeError}  Unknown attribute type.
 * @type number
 */
Message.prototype.getLength = function () {
    var len = 20; // header size (fixed)
    for (var i = 0; i < this._attrs.length; ++i) {
        var code = Const.AttrTypes[this._attrs[i].type];
        if (code < 0) {
            throw new RangeError("Unknown attribute type");
        }

        // Validate attrVal
        switch (code) {
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
Message.prototype.serialize = function () {
    var Ctor = this.constructor;
    var ctx = {
        buf: new Buffer(this.getLength()),
        pos: 0
    };
    var i;

    // Write 'Type'
    ctx.buf[ctx.pos++] = this._type >> 8;
    ctx.buf[ctx.pos++] = this._type & 0xff;
    // Write 'Length'
    ctx.buf[ctx.pos++] = (ctx.buf.length - 20) >> 8;
    ctx.buf[ctx.pos++] = (ctx.buf.length - 20) & 0xff;
    // Write 'Transaction ID'
    if (this._tid == undefined || this._tid.length != 16) {
        throw new Error("Incorrect transaction ID");
    }
    for (i = 0; i < 16; ++i) {
        ctx.buf[ctx.pos++] = this._tid[i];
    }

    for (i = 0; i < this._attrs.length; ++i) {
        var code = Const.AttrTypes[this._attrs[i].type];
        if (code < 0) {
            throw new RangeError("Unknown attribute type");
        }

        // Append attribute value
        switch (code) {
            case 0x0001: // mappedAddr
            case 0x0002: // respAddr
            case 0x0004: // sourceAddr
            case 0x0005: // changedAddr
                Ctor._writeAddr(ctx, code, this._attrs[i].value);
                break;
            case 0x0003: // changeReq
                Ctor._writeChangeReq(ctx, this._attrs[i].value);
                break;
            case 0x0032: // timestamp
                Ctor._writeTimestamp(ctx, this._attrs[i].value);
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
Message.prototype.deserialize = function (buffer) {
    var Ctor = this.constructor;
    var ctx = {
        pos:0,
        buf:buffer
    };

    // Initialize.
    this._type = 0;
    this._tid = undefined;
    this._attrs = [];

    // buffer must be >= 20 bytes.
    if (ctx.buf.length < 20)
        throw new Error("Malformed data");

    // Parse type.
    this._type = ctx.buf[ctx.pos++] << 8;
    this._type |= ctx.buf[ctx.pos++];

    // Parse length
    var len;
    len = ctx.buf[ctx.pos++] << 8;
    len |= ctx.buf[ctx.pos++];

    // Parse tid.
    this._tid = ctx.buf.slice(ctx.pos, ctx.pos + 16);
    ctx.pos += 16;

    // The remaining length should match the value in the length field.
    if (ctx.buf.length - 20 != len)
        throw new Error("Malformed data");

    while (ctx.pos < ctx.buf.length) {
        // Remaining size in the buffer must be >= 4.
        if (ctx.buf.length - ctx.pos < 4)
            throw new Error("Malformed data");

        var attrLen;
        var code;

        code = ctx.buf[ctx.pos++] << 8;
        code |= ctx.buf[ctx.pos++];
        attrLen = ctx.buf[ctx.pos++] << 8;
        attrLen |= ctx.buf[ctx.pos++];

        // Remaining size must be >= attrLen.
        if (ctx.buf.length - ctx.pos < attrLen)
            throw new Error("Malformed data: code=" + code + " rem=" + (ctx.buf.length - ctx.pos) + " len=" + attrLen);


        var attrVal;

        switch (code) {
            case 0x0001: // mappedAddAr
            case 0x0002: // respAddr
            case 0x0004: // sourceAddr
            case 0x0005: // changedAddr
                if (attrLen != 8) throw new Error("Malformed data");
                attrVal = Ctor._readAddr(ctx);
                break;
            case 0x0003: // changeReq
                if (attrLen != 4) throw new Error("Malformed data");
                attrVal = Ctor._readChangeReq(ctx);
                break;
            case 0x0032: // xorMappedAddr
                if (attrLen != 4) throw new Error("Malformed data");
                attrVal = Ctor._readTimestamp(ctx);
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

        this._attrs.push({type: Ctor._getAttrTypeByVal(code), value:attrVal});
    }
};

module.exports = Message;
