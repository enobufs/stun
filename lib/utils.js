'use strict';

exports.inetAton =
function inetAton(a) {
    var d = a.split('.');
    return ((((((+d[0])*256)+(+d[1]))*256)+(+d[2]))*256)+(+d[3]);
};

exports.inetNtoa =
function inetNtoa(n) {
    var d = n%256;
    for (var i = 3; i > 0; i--) {
        n = Math.floor(n/256);
        d = n%256 + '.' + d;
    }
    return d;
};

exports.bufferCompare =
function bufferCompare(a, b) {
    if (!Buffer.isBuffer(a)) {
        return undefined;
    }
    if (!Buffer.isBuffer(b)) {
        return undefined;
    }
    if (typeof a.equals === 'function') {
        return a.equals(b);
    }
    if (a.length !== b.length) {
        return false;
    }
    for (var i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
};

