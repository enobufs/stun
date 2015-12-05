'use strict';

var fs = require('fs');
var path = require('path');
var ini = require('ini');
var _ = require('lodash');

var root = process.cwd();
var iniPath = path.join(root, 'node-stun.ini');
var config = ini.parse(fs.readFileSync(iniPath, 'utf-8'));
var defaults = {
    primary: {
        host: '127.0.0.1',
        port: '3478'
    },
    secondary: {
        host: '127.0.0.2',
        port: '3479'
    }
};

module.exports = _.defaultsDeep(config, defaults);

