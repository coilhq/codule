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
  return { resolve, reject, promise, then:cb => promise.then(cb) }
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
            maxd *= 2
            while (hist.find(e => e.isConnectionEvent)) {
              hist.splice(hist.findIndex(e => e.isConnectionEvent), 1)
            }
            
            const i_ = i
            back.createEvent(() => connect(d).then(_ => { open = true; back.closeEvent(i_) }), true)
          } else {
            let exceeded = false
            hist.forEach(e => {
              if (!e.closed) {
                if (e.executionCount > 1) exceeded = true
                if (e.executionCount > 0) e.execute()
                
                e.executionCount++
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
        execute()
        
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
          d = Math.min((10*maxd + 2*avg) / 11, d)
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
      if (back.connected) {
        pings.push(back.createEvent(() => { ws.send('_ping') }))
      }
      ping(back, ws)
    }, 300000)
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
      } else if (command === '_ackAll') {
        sendQueue = sendQueue.filter((e, key) => {
          if (key.startsWith(ack)) {
            back.closeEvent(e)
            return false
          } else return true
        })
      } else if (command === '_pong') {
        pings.forEach(e => back.closeEvent(e))
        pings.splice(0, pings.length)
      }
    })
  }))
  
  ping(back, ws)
  
  const sentMMMM = new Map()
  
  return {
    send: (tag, m) => {
      if (sentMMMM.has(tag)) throw new Error('wtf at ' + tag)
      sentMMMM.set(tag, '')
      
      const encMes = '_mes ' + tag.length + ' ' + tag + m
      sendQueue.set(tag, back.createEvent(() => { ws.send(encMes) }))
    },
    clearEpoch: tag => {
      sendQueue.forEach((_, key) => {
        if (key.startsWith(tag)) setTimeout(() => sendQueue.delete(key), 600000)
      })
    }
  }
}

// -----------------------------------------------------------------------------

function RWebSocketServer(port, n, skey, pkey, usernames, dhkeys) {
  const server = new WebSocket.Server({ port })
  let messageListeners = new Map()
  const connectedD = [...Array(n)].map(_ => defer())

  const unhandledMessageStacks = [...Array(n)].map(_ => [ ]),
        unhandledMessageStacksLengths = [...Array(n)].map(_ => 0)
  
  server.on('connection', soc => {
    let authedAs = -1
    setTimeout(() => {
      if (authedAs === -1) soc.close()
    }, 60000)
    
    let recentPings = 0
  
    soc.on('message', data => {
      const [ command, ...params ] = data.split(' ')

      if (authedAs === -1) {
        if (command === '_open') {
          // On connection we send our public key and await auth.
          soc.send('_'+hex(pkey))
        } else if (command === '_connect') {
          // Upon receiving the auth, we verify it's the correct DH key, then
          // authorize the socket and send back an empty ack.
          const [ otherNodeRaw, receivedDhkey ] = params
          let otherNode
          try {
            otherNode = parseInt(otherNodeRaw, 10)
          } catch (e) { soc.close(); return }
          
          if (dhkeys[otherNode]) {
            if (nacl.verify(dehex(receivedDhkey), dhkeys[otherNode])) {
              soc.send('_', err => { })
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
          const tagLength = parseInt(params[0], 10),
                taggedMes = params.slice(1).join(' ')
          const tag = taggedMes.slice(0, tagLength)
          const m = taggedMes.slice(tagLength)
          
          if (messageListeners.has(tag)) {
            console.log('message accepted from ' + authedAs + ' at [' + tag + ']: ' + m)
            soc.send('_ack ' + tag, err => { })
            if (messageListeners.get(tag)(authedAs, m)) {
              setTimeout(() => messageListeners.delete(tag), 60000)
            }
          } else {
            if (unhandledMessageStacks[authedAs].some(([tag_]) => tag === tag_)) {
              soc.send('_ack ' + tag, err => { })
              return;
            }
            
            if (unhandledMessageStacksLengths[authedAs] <= 1000000-m.length-tagLength
                && unhandledMessageStacks[authedAs].length <= 1000) {
              unhandledMessageStacks[authedAs].push([tag, m])
              unhandledMessageStacksLengths[authedAs] += tagLength+m.length
              soc.send('_ack ' + tag, err => { })
            } else {
              console.log('message rejected from ' + usernames[authedAs] + ' at [' + m_[0] + ']: ' + m_[1])
            }
          }
        } else if (command === '_ping' && recentPings < 10) {
          soc.send('_pong', err => { })
          recentPings++
          setTimeout(() => recentPings--, 30000)
        }
      }
    })
  })

  return {
    connected: connectedD.map(d => d.promise),
    onMessage: (tag, cb) => {
      const recd = [...Array(n)].map(_ => false)
      let listener
      const listener_ = (i, m) => {
        if (recd[i]) return;
        cb(i, m)
        
        recd[i] = true
        return recd.every(t => t)
      }
      
      if (messageListeners.has(tag)) {
        const oldCB = messageListeners.get(tag)
        listener = (i, m) => {
          const a = oldCB(i, m)
          const b = listener_(i, m)
          return a && b
        }
      } else listener = listener_
      
      messageListeners.set(tag, listener)
      
      let heldMessages = unhandledMessageStacks.map(stack => 
        stack.find(([tag_]) => tag_ === tag))
      
      heldMessages.forEach((e, i) => { if (e) listener(i, e[1]) })
    },
    onMessageFrom: (tag, sender, cb) => {
      let recd = false
      let listener
      const listener_ = (i, m) => {
        if (i === sender && !recd) {
          cb(m)
          recd = true
          return true
        }
      }
      
      if (messageListeners.has(tag)) {
        const oldCB = messageListeners.get(tag)
        listener = (i, m) => {
          const a = oldCB(i, m)
          const b = listener_(i, m)
          return a && b
        }
      } else listener = listener_
      
      messageListeners.set(tag, listener)
      
      let heldMessages = unhandledMessageStacks.map(stack => 
        stack.find(([tag_]) => tag_ === tag))
      
      heldMessages.forEach((e, i) => { if (e) listener(i, e[1]) })
    },
    clearEpoch: tag => {
      messageListeners.forEach((_, key) => {
        if (key.startsWith(tag)) setTimeout(() => messageListeners.delete(key), 600000)
      })
    }
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
  if (!hostPairs.find(([a,b]) => a === thisUsername))
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
    broadcast: (tag, m) => outSocs.forEach(soc => soc.send(''+tag, m)),
    send: (tag, mFunc) => outSocs.forEach((soc,i) => soc.send(''+tag, mFunc(i))),
    sendTo: (tag, i, m) => outSocs[i].send(''+tag, m),
    receive: (tag, cb) => server.onMessage(''+tag, cb),
    receiveFrom: (tag, i, cb) => server.onMessageFrom(''+tag, i, cb),
    clearEpoch: tag => { server.clearEpoch(tag); outSocs.forEach(soc => soc.clearEpoch(tag)) },
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
