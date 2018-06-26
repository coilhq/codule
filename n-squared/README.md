# n-squared

A module for setting up distributed communication between Codius hosts.

This module is currently in ALPHA. It is not safe to use in a production environment. In particular, connections are done over plain websockets. Since the security of our bilateral-authentication mechanism assumes that communication is encrypted and servers are authenticated, this makes the module useless against attack attackers.

The API is modeled after a tagged-message reactive style that is commonly used in distributed systems. All messages are sent with a tag that indicates which part of the program it corresponds to. The API is designed to be asynchronously safe and reliable: message listeners can be attached before OR after the corresponding message is delivered without affecting the program; further a message sent is guaranteed to always be eventually received at the destination even if the connection is broken. If a node sends multiple messages with the same tag, all but the first message is ignored.

Messages are also labelled with an "epoch". Epochs can be cleared to keep the memory buffers bounded, but doing so risks a message that was sent not being received at the destination in periods of high asynchrony, so clearing an epoch should only be done if the other nodes can be guaranteed to "catch back up" even if the in-transit messages from that epoch are lost. If a bounded number of callbacks are attached to any given epoch and only a bounded number of epochs are active/uncleared at any given time, the memory used by the module should be guaranteed bounded even if some of the other hosts are malicious and attempting to DoS you.

Example of use:
```
const broker = require('n-squared')()

broker.receive('epoch1', 'test_tag', (i, m) => console.log('Received a test_tag message from node #' + i + ': ' + m))
broker.receive('epoch1', 'test_tag2', (i, m) => console.log('Received a test_tag2 message from node #' + i + ': ' + m))

broker.broadcast('epoch1', 'test_tag', 'Hello World!')
broker.send('epoch1', 'test_tag', i => 'Hello node #' + i)

broker.allConnected.then(() => console.log('All nodes have connected!'))
```
