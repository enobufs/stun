# STUN server for Node.js

> Looking for older implementation? Go to [legacy](https://github.com/enobufs/stun/tree/legacy) branch.

## Overview
STUN (Simple Traversal of UDP through NAT: RFC3489) is a protocol that allows a
client node to obtain an external IP address and port number assigned by a NAT
the client is behind. It can also identify behavioral type of the NAT.

## System requirement
* Node.js v0.10.x or above
* Two IP addresses on the same machine (for server)

## Installation
```
$ npm install -g node-stun
```

## Usage
### How to run STUN server
Place a config file named as `node-stun.ini` in your current directory.
The config file should look like following. (These local loopback addresses
should be routable public IP addresses in the real settings, of course)

```
[primary]
host = 127.0.0.1

[secondary]
host = 127.0.0.2
```

On Mac, you can add another loopback address by typing:

```
$ sudo ifconfig lo0 alias 127.0.0.2 up
```

The start STUN server:

```
$ node-stun-server
```


### How to run STUN client

In another terminal, type:

```
$ node-stun-client -s 127.0.0.1
```

If successful, you should see the following on your console:
```
Complete(0): Open NB=I EF=I (Open to internet) mapped=127.0.0.1:61072 rtt=0
```

### API
(TODO: Will finalize the API in the next release)


# Limitations
* Current implementation does not support RFC 5389
* Following attributes are not supported
   * RESPONSE-ADDRESS
   * USERNAME
   * PASSWORD
   * MESSAGE-INTEGRITY
   * ERROR-CODE
   * UNKNOWN-ATTRIBUTE
   * REFLECTED-FROM
   * XOR-MAPPED-ADDRESS (RFC3489bis)

# Public STUN servers that work with this STUN client
> Last tested on Jan 24, 2018

* sip1.lakedestiny.cordiaip.com
* stun.callwithus.com
* stun.counterpath.net
* stun.ideasip.com
* stun.internetcalls.com
* stun.sipgate.net
* stun.stunprotocol.org
* stun.voip.aebc.com
* stun.voipbuster.com
* stun.voxgratia.org
* stun.xten.com


# License

```
  Copyright (c) 2011 Yutaka Takeda <yt0916 at gmail.com>
  MIT Lincesed
 
  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the "Software"),
  to deal in the Software without restriction, including without limitation
  the rights to use, copy, modify, merge, publish, distribute, sublicense,
  and/or sell copies of the Software, and to permit persons to whom the
  Software is furnished to do so, subject to the following conditions:
 
  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
  IN THE SOFTWARE.
```

