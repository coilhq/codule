const broker = require('n-squared')()
const { setupHeavyCommonCoin, setupCommonCoin, keyGenAsync, thresholdECDSA, genSk, hashToScalar } = require('threshodl')
const { brachaBroadcast, brachaReceive, setupMostefaouiConsensus } = require('basic-byzantine')

function defer() {
  let resolve, reject
  const promise = new Promise((res, rej) => { resolve = res; reject = rej })
  return { resolve, reject, promise, then:(cb) => promise.then(cb) }
}

module.exports = async function () {
  const n = broker.n
  console.log = function() {}
  
  const sk = genSk()
  
  const newSk = (tag) => ((subtag) => hashToScalar(sk.encodeStr() + '||subkey||' + tag + '||subtag||' + subtag))
  
  const setupConsensus = async (tag, broker) => {
    const coin = await setupHeavyCommonCoin(tag+'hcc', broker, brachaBroadcast, brachaReceive, newSk(tag+'hcc'))
    
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
    await keyGenAsync('tagABC', broker, brachaBroadcast, brachaReceive, setupConsensus, newSk('tagABC'))
  
  console.error('secret key share: ' + sk.val.toString('hex'))
  console.error('public key: ' + pk.val.encodeCompressed('hex'))
  
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
        ABBAs.forEach((ABBA, i) => { ABBA.vote(yesVotes.includes(i)) })
      },
      result:Promise.all(ABBAs.map(c => c.result)).then(results => results.filter(t => t))
    }
  }
  
  const keyGen = (tag, broker, subtag) => {
    return keyGenAsync(tag, broker, brachaBroadcast, brachaReceive, setupFastConsensus, newSk(tag+'||'+subtag))
  }
  
  let iteration = 0
  return msg => thresholdECDSA('tagSign'+(iteration++), broker, sk, pks, msg, keyGen)
}




// const setupSigning = require('./index.js')
// let sign; setupSigning().then(s => sign = s)
// sign('bye').then(sig => console.error('signature: ' + sig))
