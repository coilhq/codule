

// ---------------------------------------------------------------

function receive(epoch, tag, broker, parse = (i, m) => m, st = () => Promise.resolve(true), oc = [], on = []) {
  return {
    parseInput: cb => {
      return receive(epoch, tag, broker, cb, st, oc)
    },
    suchThat: cb => {
      const deferredCB = (i, m) => Promise.resolve(cb(i, m))
      return receive(epoch, tag, broker, parse, (i, m) => Promise.all([ st(i, m), cb(i, m) ]).then(a => a.every(t => t)), oc)
    },
    onCount: (count, cb) => {
      return receive(epoch, tag, broker, parse, st, (oc||[]).concat([[count, cb]]))
    },
    onNew: cb => {
      return receive(epoch, tag, broker, parse, st, oc, (on||[]).concat([cb]))
    },
    onCountMatching: (count, cb) => {
      const checkMatching = (i, m, received) => {
        let matching = received.filter(m_ => m_ === m)
        if (matching.length >= count) {
          cb(m, received)
          return true
        }
      }
      
      return receive(epoch, tag, broker, parse, st, oc, (on||[]).concat([cb]))
    },
    digest:() => {
      const received = [...Array(n)]
      let count = 0
      
      broker.receive(epoch, tag, (i, m) => {
        const parsedInput = parse(i, m)
        st(i, parsedInput).then(b => {
          if (b) {
            received[i] = parsedInput
            count++
            on = on.filter(cb => !cb(i, m, received))
            
            let countedCBs = oc.filter(([count_]) => count_ <= count)
            oc = oc.filter(([count_]) => count_ > count)
            
            countedCBs.forEach(([_, cb]) => cb(received))
          }
        }
      })
    }
  }
}

// ---------------------------------------------------------------

function brachaBroadcast(epoch, tag, m, broker) {
  if (typeof m === 'string')
    broker.broadcast(epoch, tag+'i', m)
  else
    broker.send(epoch, tag+'i', m)
}

function brachaReceive(epoch, tag, sender, broker, parseInput = m => Promise.resolve(m), didntEcho) {
  const f = (broker.n-1)/3|0, n = broker.n
  const result = defer()
  
  let echoed = false, readied = false
  let echoesReceived;
  
  broker.receiveFrom(epoch, tag+'i', sender, m => {
    parseInput(m, defer()).then(pm => {
      if (!echoed && pm) {
        broker.broadcast(epoch, tag+'e', pm)
        echoed = true
      }
    }
  })
  
  receive(epoch, tag+'e', broker)
    .onCountMatching(n-f, (m, received) => {
      echoesReceived = received
      if (!readied) {
        broker.broadcast(epoch, tag+'r', m)
        readied = true
      }
    }).digest()
  
  receive(epoch, tag+'r', broker)
    .onCountMatching(f+1, (m, received) => {
      if (!readied) {
        broker.broadcast(epoch, tag+'r', m)
        readied = true
      }
    }).onCountMatching(n-f, (m, received) => {
      if (echoesReceived && didntEcho) didntEcho.resolve([ m, echoesReceived ])
      
      result.resolve(m)
    }).digest()
  
  return result
}
