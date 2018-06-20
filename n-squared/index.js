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

// Basic websocket emulator that handles connecting to unopened servers
// and reconnecting when the connection goes down automatically.
function RWebSocket(target) {
  let delay1 = 1, delay2 = 0
  
  function tryOpen() {
    const ws = new WebSocket(target)
    const ret = defer()
    
    ws.on('open', () => {
      console.log('opened socket to remote peer.')
      ret.resolve(ws)
    })
    ws.on('error', err => {
      // n^2 backoff, capped at 5 minutes
      ;[ delay1, delay2 ] = [ 2*delay1-delay2+2, delay1 ]
      setTimeout(() => ret.resolve(tryOpen()), Math.min(delay1, 300000))
    })
    
    return ret.promise
  }

  const socp = tryOpen()
  
  return {
    send: m => socp.then(ws => ws.send(m)),
    onmessage: cb => socp.then(ws => ws.on('message', cb)),
    once: cb => socp.then(ws => ws.once('message', cb)),
    destroy: () => socp.then(ws => ws.close())
  }
}

// -----------------------------------------------------------------------------

// Upon receiving the public key of the node being connected to, sends
// the shared Diffie-Hellman key as an authentication mechanism.
// Once we receive an acknowledgement that the auth succeeded, we begin
// sending messages normally.
function authOut(peerName, skey, thisHostIndex, soc) {
  const dhkey = defer(), authedSoc = defer()
  soc.once(peerpkey => {
    if (peerpkey.length !== 2*nacl.scalarMult.groupElementLength) {
      console.error('\x1b[31m%s\x1b[0m', 'Invalid public key received from '
                                            +peerName+'! (' + peerpkey + ')')
      soc.destroy()
      return
    }
    
    const dhkeyVal = nacl.scalarMult(skey, dehex(peerpkey))
    soc.send('_connect '+thisHostIndex+' '+hex(dhkeyVal))
    console.log('\x1b[36m%s\x1b[0m', 'Successfully connected to ' + peerName + '.')
    dhkey.resolve(dhkeyVal)
    soc.once(m => authedSoc.resolve(soc))
  })
  
  return { dhkey:dhkey.promise, soc:authedSoc.promise }
}

// -----------------------------------------------------------------------------

function encodeTag (tag, message) {
  return tag.length+' '+tag+message
}

function decodeTag (data) {
  const [ length, ...taggedMessageA] = data.split(' ')
  const taggedMessage = taggedMessageA.join(' ')
  const tag = taggedMessage.slice(0, length)
  const message = taggedMessage.slice(length)
  return { tag, message }
}

// Stores a map of promises that allows asynchronous message receipt.
// Attaching a listener for a certain tag can be done before
// or after that message is received with no issue.
function createMessageHandler() {
  let map = asyncMap()
  const itag = (hostIndex, tag) => hostIndex+':'+tag
  return {
    receiveMessage: (hostIndex, tag, message) => map.set(itag(hostIndex, tag), message),
    onMessage: (hostIndex, tag, cb) => map.get(itag(hostIndex, tag)).then(cb)
  }
}

// -----------------------------------------------------------------------------

// Opens websocket connections with the other hosts and returns a sterile
// interface for interacting with these hosts and adding reactive logic
// when messages are received.
module.exports = function getBroker() {
  const thisHostName = process.env.CODIUS_HOST
  const hostNames = JSON.parse(process.env.CONTRACT_INSTANCES)
  if (!hostNames.includes(thisHostName)) hostNames.push(thisHostName)
  hostNames.sort()
  
  const thisHostIndex = hostNames.indexOf(thisHostName)
  const hosts = hostNames.map(hostStr => {
    const hostProtocol = 'ws://'
    const hostHash = process.env.CODIUS ? process.env.CODIUS_MANIFEST_HASH + '.' : ''
    hostStr = hostProtocol + hostHash + hostStr
    return new url.URL(hostStr)
  })
  const thisHost = new url.URL(thisHostName)
  // TODO: const skey = easyrand(nacl.scalarMult.scalarLength)
  const skey = nacl.randomBytes(nacl.scalarMult.scalarLength)
  const pkey = nacl.scalarMult.base(skey)
  const rawOutSockets = hosts.map(host => new RWebSocket(host))
  const authedSockets = rawOutSockets.map((soc,i) => {
                          soc.send('_open')
                          return authOut(hostNames[i], skey, thisHostIndex, soc)
                        })

  const messageHandler = createMessageHandler()

  const server = new WebSocket.Server({ port:Number(thisHost.port) })
  server.on('connection', soc => {
    let authed = -1
    const messageQueue = new Map()
  
    soc.on('message', data => {
      console.log('message received: ' + data)
      const [ command, ...params ] = data.split(' ')

      if (command === '_open') {
        // On connection we send our public key and await auth.
        soc.send(hex(pkey))
      } else if (command === '_connect') {
        // Upon receiving the auth, we verify it's the correct DH key, then
        // authorize the socket and send back an empty ack.
        const [ otherNode, receivedDhkey ] = params
        
        authedSockets[otherNode].dhkey.then(dhkey => {
          if (nacl.verify(dehex(receivedDhkey), dhkey)) {
            soc.send('')
            authed = otherNode
            console.log('\x1b[36m%s\x1b[0m', hostNames[otherNode] + ' connected successfully.')
          } else {
            soc.destroy()
            console.log('\x1b[31m%s\x1b[0m', 'Failed to authenticate incoming connection.')
          }
        })
      } else if (authed !== -1) {
        // Handle the message only if the socket has already been authed.
        const { tag, message } = decodeTag(data)
        messageHandler.receiveMessage(authed, tag, message)
      }
    })
  })
  
  // Send functions that can be called at any time and only send
  // the message AFTER the receiver connects
  const sendArray = authedSockets.map(connected => 
    (tag, message) => connected.soc.then(soc => 
      soc.send(encodeTag(tag, message), error => { })))
  
  return {
    send: (tag, mFunc) => sendArray.forEach((send, i) => send(tag, mFunc(i))),
    broadcast: (tag, m) => sendArray.forEach(send => send(tag, m)),
    receive: (tag, cb) => hostNames.map((_,i) => messageHandler.onMessage(i, tag, m=>cb(i, m))),
    allConnected:Promise.all(authedSockets.map(a => a.soc)).then(() => undefined)
  }
}
