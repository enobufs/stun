'use strict';

var util = require('util');

exports.create =
function create(emitter) {
    var logger = {};
    ['debug', 'warn', 'info', 'error'].forEach(function (level) {
        logger[level] = function () {
            emitter.emit('log', {
                level: level,
                message: util.format.apply(this, arguments)
            });
        };
    });

    return logger;
};
