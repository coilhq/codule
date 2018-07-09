

// ---------------------------------------------------------------

function defer() {
  let resolve, reject
  const promise = new Promise((res, rej) => { resolve = res; reject = rej })
  return { resolve, reject, promise, then:(cb) => promise.then(cb) }
}

function receive(tag, broker, parse = (i, m) => m, st = () => Promise.resolve(true), oc = [], on = []) {
  return {
    parseInput: cb => {
      return receive(tag, broker, cb, st, oc, on)
    },
    suchThat: cb => {
      const deferredCB = (i, m) => Promise.resolve(cb(i, m))
      return receive(tag, broker, parse, (i, m) => Promise.all([ st(i, m), cb(i, m) ]).then(a => a.every(t => t)), oc, on)
    },
    onCount: (count, cb) => {
      return receive(tag, broker, parse, st, (oc||[]).concat([[count, cb]]), on)
    },
    onNew: cb => {
      return receive(tag, broker, parse, st, oc, (on||[]).concat([cb]))
    },
    onCountMatching: (count, cb) => {
      const checkMatching = (i, m, received) => {
        let matching = received.filter(m_ => m_ === m)
        if (matching.length >= count) {
          cb(m, received)
          return true
        }
      }
      
      return receive(tag, broker, parse, st, oc, (on||[]).concat([checkMatching]))
    },
    digest:() => {
      const received = [...Array(broker.n)]
      let count = 0
      
      broker.receive(tag, (i, m) => {
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
        })
      })
    }
  }
}

// ---------------------------------------------------------------

function brachaBroadcast(tag, m, broker) {
  if (typeof m === 'string')
    broker.broadcast(tag+'i', m)
  else
    broker.send(tag+'i', m)
}

function brachaReceive(tag, sender, broker, parseInput = m => m, didntEcho) {
  const f = (broker.n-1)/3|0, n = broker.n
  const result = defer()
  
  let echoed = false, readied = false
  let echoesReceived;
  
  broker.receiveFrom(tag+'i', sender, m => {
    Promise.resolve(parseInput(m))
      .then(pm => {
      if (!echoed && pm) {
        broker.broadcast(tag+'e', pm)
        echoed = true
      }
    })
  })
  
  receive(tag+'e', broker)
    .onCountMatching(n-f, (m, received) => {
      echoesReceived = received
      if (!readied) {
        broker.broadcast(tag+'r', m)
        readied = true
      }
    }).digest()
  
  receive(tag+'r', broker)
    .onCountMatching(f+1, (m, received) => {
      if (!readied) {
        broker.broadcast(tag+'r', m)
        readied = true
      }
    }).onCountMatching(n-f, (m, received) => {
      if (echoesReceived && didntEcho)
        didntEcho.resolve([ m, [...Array(n)].map((_,i) => i).filter(i => !echoesReceived[i]) ])
      
      result.resolve(m)
    }).digest()
  
  return result.promise
}

// Cut down version of Moustefaoui et al.'s updated binary consensus. For some reason
// the updated algorithm makes the round function twice as long as it needs to be;
// a single DSBV instance per round suffices.
function setupMostefaouiConsensus(tag, broker, coin) {
  const n = broker.n, f = (n-1)/3|0
  let result = defer()
    
  let finald = false, finished = false, voted = false
  
  async function vote(est_i) {
    if (voted) return;
    voted = true
    
    if (est_i === true) est_i = 1
    if (est_i === false) est_i = 0
    
    if (est_i !== 1 && est_i !== 0)
      throw new Error('invalid vote for binary consensus')
    
    receive(tag+'f', broker)
      .onCountMatching(f+1, m => {
        if (!finald) {
          broker.broadcast(tag+'f', m)
          finald = true
        }
      })
      .onCountMatching(n-f, m => {
        finished = true
        result.resolve(parseInt(m))
      })
      .digest()
    
    for (let i = 0; !finished; i++) {
      const roundResult = defer()
      
      function SBV(tag, vote, voteName) {
        const SBVResult = defer()
        let auxed = false, voted = [ false, false ]
        
        broker.broadcast(tag+'b'+i+'_'+vote, voteName)
        
        const bin_values = [ defer(), defer() ]
        receive(tag+'b'+i+'_'+(1-vote), broker)
          .onCountMatching(f+1, (m) => {
            broker.broadcast(tag+'b'+i+'_'+(1-vote), m)
          })
          .digest()
          
        ;([0, 1]).forEach(async (j) => {
          receive(tag+'b'+i+'_'+j, broker)
            .onCountMatching(n-f, (m) => {
              if (!auxed) {
                broker.broadcast(tag+'a'+i, ''+j)
                auxed = true
              }
              
              bin_values[j].resolve(m)
            })
            .digest()
          
          const jName = await bin_values[j].promise
          
          receive(tag+'a'+i, broker)
            .suchThat((i, m) => m === ''+j)
            .onCount(n-f, () => {
              SBVResult.resolve([j, jName])
            })
            .digest()
        })
                             
        Promise.all(bin_values.map(p => p.promise))
          .then((zeroName, oneName) => {
          receive(tag+'a'+i, broker)
            .onCount(n-f, () => {
              SBVResult.resolve([2, zeroName, oneName])
            })
            .digest()
        })
        
        return SBVResult.promise
      }
      
      const [ mid ] = await SBV(tag+'1', est_i, '')
      const [ final, zeroName ] = await SBV(tag+'2', (mid === 2) ? 1 : 0, (mid !== 2) ? ''+mid : '')
      
      const v = parseInt(zeroName)
      if (final === 0) {
        est_i = v
        if (!finald) {
          broker.broadcast(tag+'f', ''+v)
          finald = true
        }
      } else {
        const s = coin(tag+'c'+i)
        
        if (final === 2) {
          est_i = await s
        } else {
          est_i = v
        }
      }
    }
  }
  
  return {
    vote,
    result:result.promise
  }
}

module.exports = {
  brachaBroadcast,
  brachaReceive,
  setupMostefaouiConsensus
}

// const broker = require('n-squared')(); const { setupHeavyCommonCoin } = require('threshodl'); const { brachaBroadcast, brachaReceive } = require('basic-byzantine')

// let coin = setupHeavyCommonCoin('tagXYZ', broker, brachaBroadcast, brachaReceive)
