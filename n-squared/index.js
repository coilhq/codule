"use strict"
process.on('unhandledRejection', console.error)

const url = require('url')
const WebSocket = require('ws')

const nacl = require('tweetnacl')

// NOTE: these conversions might not be constant-time. Do not use on secets.
function hex(bytes) {
  return Array.from(bytes).map(byte => byte.toString(16).padStart(2, '0')).join('')
}

function dehex(hexstr) {
  return new Uint8Array(hexstr.match(/.{1,2}/g).map(byte => parseInt(byte, 16)))
}

// -----------------------------------------------------------------------------

// Creates a promise that can be resolved independently of its creation.
// Useful for creating promises that resolve upon receiving some message.
function defer() {
  let resolve, reject
  const promise = new Promise((res, rej) => { resolve = res; reject = rej })
  return { resolve, reject, promise, then:promise.then }
}

// A map of deferred promises. get(key) returns a promise that is resolved to
// value once set(key, value) is called, independent of which is called first.
function asyncMap() {
  const promiseMap = new Map()
  return {
    set: (key, value) => {
      if (!promiseMap.has(key)) promiseMap.set(key, defer())
      promiseMap.get(key).resolve(value)
    },
    get: (key) => {
      if (!promiseMap.has(key)) promiseMap.set(key, defer())
      return promiseMap.get(key).promise
    }
  }
}

// -----------------------------------------------------------------------------

// Websocket wrapper that handles connecting to unopened servers, authenticating,
// and reconnecting when the connection goes down automatically.
// Provides an abstract implementation of the "reliable channel" assumption;
// i.e., any message sent is guaranteed to eventually be delivered.
function RWebSocket(thisHostIndex, target, peerName, skey, onAddDhKey) {
  function backoff(connect) {
    let d = 400, maxd = 4000, avg = 400, i = 0, hist = [], open = false
    
    function loop() {
      setTimeout(() => {
        if (hist.filter(e => !e.closed).length > 0) {
          if (d >= maxd) {
            console.log('\x1b[31m%s\x1b[0m', 'connection to ' + peerName + ' timed out. reconnecting...')
            open = false
            maxd *= 1.5
            while (hist.find(e => e.isConnectionEvent)) {
              hist.splice(hist.findIndex(e => e.isConnectionEvent), 1)
            }
            
            const i_ = i
            back.createEvent(() => connect(d).then(_ => { open = true; back.closeEvent(i_) }), true)
          } else {
            let exceeded = false
            hist.forEach(e => {
              if (!e.closed) {
                if (e.executionCount > 0) exceeded = true
                e.executionCount++
                
                e.execute()
              }
            })

            if (exceeded) {
              d = Math.pow(Math.cbrt(d)+1, 3)
            }
          }
        }
        
        loop()
      }, d)
    }

    const back = {
      createEvent: (execute, conn = false) => {
        const e = {
          index: i++,
          executionCount: 0,
          startTime: new Date(),
          totalTime: 0,
          execute,
          closed: false,
          isConnectionEvent: conn
        }
        
        hist.push(e)
        
        return e.index
      },
      closeEvent: (index) => {
        const e = hist.find(_e => _e.index === index)
        if (!e) return;

        e.closed = true
        e.totalTime = new Date() - e.startTime
        
        const closedHist = hist.filter(e => e.closed)

        while(closedHist.length > 100) {
          hist.splice(hist.indexOf(closedHist.shift()), 1)
        }
        
        avg = closedHist.reduce((s, _e) => s + _e.totalTime) / closedHist.length
        if (closedHist.length >= 50) {
          d = Math.min((10*maxd + avg) / 11, d)
          maxd = Math.min((50*maxd + d*10) / 51, maxd)
        }
      },
      connected: () => open
    }
    
    const i_ = i
    back.createEvent(() => connect(d).then(_ => { open = true; back.closeEvent(i_) }), true)
    loop()
    
    return back
  }

  function authSoc(soc) {
    const authed = defer()
    soc.once('message', peerpkey => {
      // Remove underscore
      peerpkey = peerpkey.substring(1)

      if (peerpkey.length !== 2*nacl.scalarMult.groupElementLength) {
        console.error('\x1b[31m%s\x1b[0m', 'invalid public key received from '
                                              +peerName+'! (' + peerpkey + ')')
        soc.close()
        return
      }
      
      const dhkey = nacl.scalarMult(skey, dehex(peerpkey))
      soc.send('_connect '+thisHostIndex+' '+hex(dhkey), err => { })
      onAddDhKey(dhkey)
      soc.once('message', _ => {
        authed.resolve()
        console.log('\x1b[36m%s\x1b[0m', 'successfully connected to ' + peerName + '.')
      })
    })

    soc.send('_open', err => { })
    
    return authed.promise
  }
  
  function tryOpen(d) {
    const startTime = new Date()
    const ws = new WebSocket(target, [], { handshakeTimeout: d - 10 })
    const ret = defer()
    
    ws.on('open', () => {
      let authed = false
      ret.resolve(authSoc(ws).then(_ => { authed = true; return ws }))
      
      setTimeout(() => { if (!authed) ws.close() }, d - (new Date() - startTime))
    })

    ws.on('error', err => {
      console.log('outgoing socket error.')
    })
    
    return ret.promise
  }
  
  const pings = [ ]

  function ping(back, ws) {
    setTimeout(() => {
      if (back.connected)
        pings.push(back.createEvent(() => ws.send('_ping')))
      ping(back, ws)
    }, 30000)
  }
  
  let ws = { send: m => { } }, sendQueue = new Map()
  const back = backoff(d => tryOpen(d).then(_ws => {
    ws.send = m => _ws.send(m, err => { })
    _ws.on('message', data => {
      const [ command, ...ackS ] = data.split(' ')
      const ack = ackS.join(' ')

      if (command === '_ack') {
        if (!sendQueue.has(ack)) return;

        let e = sendQueue.get(ack)
        sendQueue.delete(ack)
        back.closeEvent(e)
      } else if (command === '_pong') {
        pings.forEach(e => back.closeEvent(e))
        pings.splice(0, pings.length)
      }
    })
  }))
  
  ping(back, ws)
  
  return {
    send: (epoch, tag, m) => {
      const encMes = '_mes ' + epoch.length + ' ' + tag.length + ' ' + epoch + tag + m
      sendQueue.set(epoch.length + ' ' + epoch + tag, back.createEvent(() => ws.send(encMes)))
    },
    clearEpoch: epoch => sendQueue.forEach((_, key) => {
      if (key.startsWith(epoch.length + ' ' + epoch)) sendQueue.delete(key)
    })
  }
}

// -----------------------------------------------------------------------------

function RWebSocketServer(port, n, skey, pkey, usernames, dhkeys) {
  const server = new WebSocket.Server({ port })
  let messageListeners = new Map()
  const connectedD = [...Array(n)].map(_ => defer())

  server.on('connection', soc => {
    let authedAs = -1
  
    soc.on('message', data => {
      const [ command, ...params ] = data.split(' ')

      if (authedAs === -1) {
        if (command === '_open') {
          // On connection we send our public key and await auth.
          soc.send('_'+hex(pkey))
        } else if (command === '_connect') {
          // Upon receiving the auth, we verify it's the correct DH key, then
          // authorize the socket and send back an empty ack.
          const [ otherNode, receivedDhkey ] = params
          
          if (dhkeys[otherNode]) {
            if (nacl.verify(dehex(receivedDhkey), dhkeys[otherNode])) {
              soc.send('_')
              authedAs = otherNode
              connectedD[otherNode].resolve()
              console.log('\x1b[36m%s\x1b[0m', usernames[otherNode] + ' connected successfully.')
            } else {
              soc.close()
              console.log('\x1b[31m%s\x1b[0m', 'failed to authenticate an incoming connection.')
            }
          } else {
            soc.close()
          }
        }
      } else {
        if (command === '_mes') {
          const epochLength = parseInt(params[0], 10), 
                tagLength = parseInt(params[1], 10),
                taggedMes = params.slice(2).join(' ')
          const epoch = taggedMes.slice(0, epochLength)
          const tag = taggedMes.slice(epochLength, epochLength + tagLength)
          const m = taggedMes.slice(epochLength + tagLength)
          const epochTag = epochLength + ' ' + epoch + tag
          console.log('message received from ' + usernames[authedAs] + ' at [' + epoch + ', ' + tag + ']: ' + m)
          
          if (messageListeners.has(epochTag)) {
            soc.send('_ack ' + epochTag, err => { })
            if (messageListeners.get(epochTag)(authedAs, m)) {
              setTimeout(() => messageListeners.delete(epochTag), 60000)
            }
          }
        } else if (command === '_ping') {
          soc.send('_pong', err => { })
        }
      }
    })
  })

  return {
    connected: connectedD.map(d => d.promise),
    onMessage: (epoch, tag, cb) => {
      const epochTag = epoch.length + ' ' + epoch + tag
      const recd = [...Array(n)].map(_ => false)
      const listener = (i, m) => {
        if (!recd[i]) cb(i, m)
        
        recd[i] = true
        return recd.every(t => t)
      }
      
      messageListeners.set(epochTag, listener)
    },
    clearEpoch: epoch => messageListeners.forEach((_, key) => {
      if (key.startsWith(epoch.length + ' ' + epoch)) messageListeners.delete(key)
    })
  }
}

// -----------------------------------------------------------------------------

// Opens websocket connections with the other hosts and returns a sterile
// interface for interacting with these hosts and adding reactive logic
// when messages are received.
module.exports = function getBroker() {
  const thisUsername = process.env.USERNAME
  const thisHostName = process.env.CODIUS_HOST
  let hostPairs = JSON.parse(process.env.CONTRACT_INSTANCES)
  if (!hostPairs.find(([a,b]) => a === thisUsername && b === thisHostName))
    hostPairs.push([thisUsername, thisHostName])
  hostPairs = hostPairs.map(([a]) => a).sort().map(a => hostPairs.find(([_a]) => a === _a))
  const usernames = hostPairs.map(([a]) => a)

  const n = usernames.length
  
  const thisHostIndex = usernames.indexOf(thisUsername)
  
  const hosts = hostPairs.map(([_, hostStr]) => new url.URL(hostStr))
  const thisHost = new url.URL(thisHostName)
  hosts.forEach(host => {
    host.protocol = 'ws:'
    host.host = process.env.CODIUS ? process.env.CODIUS_MANIFEST_HASH + '.' + host.host
                                   : host.host
  })

  const skey = nacl.randomBytes(nacl.scalarMult.scalarLength)
  const pkey = nacl.scalarMult.base(skey)

  const dhkeys = [...Array(n)]

  const outSocs = hosts.map((host, i) => 
      RWebSocket(thisHostIndex, host, usernames[i], skey, dhkey => { dhkeys[i] = dhkey }))
  
  const server = RWebSocketServer(process.env.PORT, n, skey, pkey, usernames, dhkeys)
  
  return {
    broadcast: (epoch, tag, m) => outSocs.forEach(soc => soc.send(''+epoch, ''+tag, m)),
    send: (epoch, tag, mFunc) => outSocs.forEach((soc,i) => soc.send(''+epoch, ''+tag, mFunc(i))),
    sendTo: (epoch, tag, i, m) => outSocs[i].send(''+epoch, ''+tag, m),
    receive: (epoch, tag, cb) => server.onMessage(''+epoch, ''+tag, cb),
    allConnected: Promise.all(server.connected).then(() => undefined),
    kConnected: k => {
      const ret = defer()
      let c = 0
      server.connected.forEach(p => p.then(() => { c++; if (c>=k) ret.resolve() }))
      return ret.promise
    },
    thisHostIndex,
    n
  }
}
