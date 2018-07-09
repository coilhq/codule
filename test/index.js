const broker = require('n-squared')()
const { setupHeavyCommonCoin, setupCommonCoin, keyGenAsync, thresholdECDSA } = require('threshodl')
const { brachaBroadcast, brachaReceive, setupMostefaouiConsensus } = require('basic-byzantine')

function defer() {
  let resolve, reject
  const promise = new Promise((res, rej) => { resolve = res; reject = rej })
  return { resolve, reject, promise, then:(cb) => promise.then(cb) }
}

module.exports = async function () {
  const n = broker.n
  console.log = function() {}
  
  /*
  const coinInstances = [...Array(1000)]
  for (let i = 0; i < 1000; i++) {
    console.error('starting flip #' + i)
    coinInstances[i] = coin('test'+i)
    if (i % 100 === 99) await Promise.all(coinInstances.slice(0, i))
  }
  
  const flips = await Promise.all(coinInstances)
  
  console.error('\x1b[36m%s\x1b[0m', 'total heads: ' + flips.reduce((c, t) => t ? c+1 : c, 0))*/
  
  const setupConsensus = async (tag, broker) => {
    const coin = await setupHeavyCommonCoin(tag+'hcc', broker, brachaBroadcast, brachaReceive)
    
    const sharedCoinsQueried = new Map()
    const sharedCoins = [...Array(n)].map((_, i) => {
      return (tag_) => {
        if (!sharedCoinsQueried.has(tag_)) {
          sharedCoinsQueried.set(tag_, [ [...Array(n)].map(() => false), defer() ])
        }
        
        sharedCoinsQueried.get(tag_)[i][0] = true
        if (sharedCoinsQueried.get(tag_).every(([t]) => t)) {
          sharedCoinsQueried.delete(tag_)
          sharedCoinsQueried.get(tag_)[i][1].resolve(coin(tag_))
        }
        
        return sharedCoinsQueried.get(tag_)[i][1]
      }
    })
    
    const ABBAs = [...Array(n)].map((_, i) => 
      setupMostefaouiConsensus(tag+'c'+i, broker, sharedCoins[i]))
    
    return {
      vote:yesVotes => {
        ;[...Array(n)].forEach((_, i) => ABBAs[i].vote(yesVotes.includes(i)))
      },
      result:Promise.all(ABBAs.map(c => c.result)).then(results => results.filter(t => t))
    }
  }
  
  const { share:sk, sharePKs:pks, pk } = 
    await keyGenAsync('tagABC', broker, brachaBroadcast, brachaReceive, setupConsensus)
  
  console.error(sk.val)
  console.error(pk.val)
  
  const setupFastConsensus = async (tag, broker) => {
    const coin = await setupCommonCoin(tag+'hcc', broker, sk, pks)
    
    const sharedCoinsQueried = new Map()
    const sharedCoins = [...Array(n)].map((_, i) => {
      return (tag_) => {
        if (!sharedCoinsQueried.has(tag_)) {
          sharedCoinsQueried.set(tag_, [ [...Array(n)].map(() => false), defer() ])
        }
        
        sharedCoinsQueried.get(tag_)[i][0] = true
        if (sharedCoinsQueried.get(tag_).every(([t]) => t)) {
          sharedCoinsQueried.delete(tag_)
          sharedCoinsQueried.get(tag_)[i][1].resolve(coin(tag_))
        }
        
        return sharedCoinsQueried.get(tag_)[i][1]
      }
    })
    
    const ABBAs = [...Array(n)].map((_, i) => 
      setupMostefaouiConsensus(tag+'c'+i, broker, sharedCoins[i]))
    
    return {
      vote:yesVotes => {
        ;[...Array(n)].forEach((_, i) => ABBAs[i].vote(yesVotes.includes(i)))
      },
      result:Promise.all(ABBAs.map(c => c.result)).then(results => results.filter(t => t))
    }
  }
  
  const keyGen = (tag, broker) => {
    let kg = keyGenAsync(tag, broker, brachaBroadcast, brachaReceive, setupFastConsensus)
    kg.then(result => console.error('HAHAHAHAHAHAHA ' + tag))
    return kg
  }
  
  let iteration = 0
  return msg => thresholdECDSA('tagSign'+(iteration++), broker, sk, pks, msg, keyGen)
}




// const setupSigning = require('./index.js')
// let sign; setupSigning().then(s => sign = s)
// sign('bye').then(sig => console.error(sig))
