# STUN server for Node.js


## Overview
STUN (Simple Traversal of UDP through NAT: RFC3489) is a protocol that allows a client node to obtain an external IP address and port number assigned by a NAT the client is behind. It can also identify behavioral type of the NAT. It is implemented in JavaScript to run with node.js. I started this work originally to learn node.js and JavaScript, however, this library may help other people who are interested in using STUN.

## System requirement
* Node.js v0.10 or above 
* Two IP addresses on the same machine (for server)

## Source tree
* <root>/lib/stun.js ... STUN library used for both client and server.
* <root>/samples/stunClient.js ... Sample STUN client implementation.
* <root>/samples/stunServer.js ... Sample STUN server implementation.
* <root>/samples/stunServer.conf ... Server config file loaded by stunServer.js.

## How to run STUN server

(1) Modify stunServer.conf to specify your IP addresses on the server.
(2) Run stunServer.js (> node stunServer.js)

That is it!

# Limitations
* Current implementation does not support RFC 5389
* Following attributes are not supported
   * RESPONSE-ADDRESS
   * CHANGED-ADDRESS
   * USERNAME
   * PASSWORD
   * MESSAGE-INTEGRITY
   * ERROR-CODE
   * UNKNOWN-ATTRIBUTE
   * REFLECTED-FROM
   * XOR-MAPPED-ADDRESS (RFC3489bis)

# License
MIT Licensed

# CONTRIBUTORS WANTED!!
Please contact me.

