# STUN server for Node.js

## Overview
STUN (Simple Traversal of UDP through NAT: RFC3489) is a protocol that allows a
client node to obtain an external IP address and port number assigned by a NAT
the client is behind. It can also identify behavioral type of the NAT.

## System requirement
* Node.js v0.10.x or above
* Two IP addresses on the same machine (for server)

## Installation
```
$ npm install node-stun
```

## How to run STUN server
(TODO)


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

# CONTRIBUTORS WANTED!!
Please contact me.

