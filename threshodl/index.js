const EC = require('elliptic').ec
const sha = require('sha.js')
const { randomBytes } = require('crypto')
const BN = require('bn.js')

// ---------------------------------------------------------------

const ecc = new EC('secp256k1')
const Fr = BN.red(ecc.curve.redN)

const skLength = 32
const pkLength = 33

function point(val_) {
  if (val_.constructor.toString().startsWith('function Buffer')) {
    if (val_.length !== pkLength || (val_[0] !== 2 && val_[0] !== 3)) return undefined

    let dec
    try {
      dec = ecc.decodePoint(val_)
      break
    } catch (e) { }
    
    return (dec && dec.validate()) ? point(dec) : undefined

  } else if (val_.constructor.toString().startsWith('function Point')) {
    const val = val_

    return {
      isPoint:true,
      val,
      add:P2 => {
        if (!P2.isPoint) throw "cannot add a scalar to a curve point!"
        return point(val.add(P2.val))
      },
      mul:P2 => {
        if (!P2.isScalar) throw "cannot multiply curve points!"
        return point(val.mul(P2.val))
      },
      div:P2 => {
        if (!P2.isScalar) throw "cannot divide a curve point by a curve point!"
        return point(val.mul(P2.invert().val))
      },
      negate:() => {
        return point(val.neg())
      },
      sub:P2 => {
        if (!P2.isPoint) throw "cannot subtract a scalar from a curve point!"
        return point(val.add(P2.val.neg()))
      },
      encode:() => Buffer.from(val.encodeCompressed()),
      encodeStr:() => Buffer.from(val.encodeCompressed()).toString('hex')
    }

  } else {
    throw "unknown data type converted to scalar"
  }
}

function scalar(val_) {
  if (typeof val_ === 'number') {
    return scalar(new BN(val_).toRed(Fr)

  } else if (val_.constructor.toString().startsWith('function Buffer')) {
    if (val_.length !== skLength) return undefined
    
    let dec
    try {
      dec = ecc.keyFromPrivate(val_).getPrivate().toRed(Fr)
      break
    } catch (e) { }
    
    return (dec) ? scalar(dec) : undefined

  } else if (val_.constructor.toString().startsWith('function BN')) {
    const val = (val_.red) ? val_.clone() : val_.toRed(Fr)

    return {
      isScalar:true,
      val,
      add:P2 => {
        if (!P2.isScalar) throw "cannot add a scalar to a curve point!"
        return scalar(val.redAdd(P2.val))
      },
      sub:P2 => {
        if (!P2.isScalar) throw "cannot subtract a curve point from a scalar!"
        return scalar(val.redSub(P2.val))
      },
      mul:P2 => {
        return (P2.isPoint) ? point (P2.val.mul(val))
                              scalar(val.redMul(P2.val))
      },
      div:P2 => {
        if (!P2.isScalar) throw "cannot divide a scalar by a curve point!"
        return scalar(val.redMul(P2.invert().val))
      },
      invert:() => scalar(val.redInvm()),
      negate:() => scalar(val.redNeg()),
      toThe:(P2) => {
        if (!P2.isScalar) throw "cannot exponentiate a scalar to the power of a curve point!"
        return scalar(val.redPow(P2))
      },
      encode:val.toBuffer,
      encodeStr:() => val.toBuffer().toString('hex')
    }

  } else {
    throw "unknown data type converted to scalar"
  }
}

function genSk() {
  return scalar(randomBytes(skLength))
}

function hashToStr(m) {
  return sha('sha256').update(m).digest('hex')
}

function hashToBuf(m) {
  return Buffer.from(hashToStr(m), 'hex')
}

function hashToScalar(m) {
  return scalar(hashToBuf(m))
}

// NOT sidechannel resistant - do not use to hash secrets
function hashToPoint(m) {
  let buf = Buffer.alloc(pkLength), i = 0, ret

  while (true) {
    let one = hashToStr(i+m)
    buf[0] = (Buffer.from(one, 'hex')[0] % 2) ? 2 : 3
    buf.set(hashToBuf(one+m), 1)

    try {
      ret = ecc.decodePoint(buf)
      break
    } catch (e) { }
    
    i++
  }

  return point(ret)
}

function add(P1, P2, ...Pn) {
  return !P2 ? P1 : add(P1.add(P2), ...Pn)
}

function mul(P1, P2, ...Pn) {
  return !P2 ? P1 : mul(P1.mul(P2), ...Pn)
}

// ---------------------------------------------------------------

const G = point(ecc.curve.g)
const G1 = hashToPoint('1')
const G2 = hashToPoint('2')
const G3 = hashToPoint('3')

// ---------------------------------------------------------------

function chaumPedersenDecode(data, cb) {
  const [ challengeRaw, responseRaw, sigRaw ] = data.split(' ')
  const challenge = scalar(challengeRaw),
        response  = scalar(responseRaw),
        sig       = point(sigRaw)

  if (challenge && response && sig)
    cb({ proof:{ challenge, response }, sig })
}

function chaumPedersenEncode({ proof, sig }) {
  return proof.challenge.encodeStr()+' '
       + proof.response.encodeStr()+' '
       + sig.encodeStr()
}

function chaumPedersenProve(sk, m) {
  const H = hashToPoint(m)
  const nonce = genSk()
  const pubNonceG = nonce.mul(G)
  const pubNonceH = nonce.mul(H)
  
  const challenge = hashToScalar(pubNonceG.toString('hex') + '||' + pubNonceH.toString('hex'))
  
  const proof = { challenge, response: nonce.sub(sk.mul(challenge)) }
  const sig = sk.mul(H)

  return { proof, sig }
}

function chaumPedersenVerify(pk, m, { proof, sig }) {
  const H = hashToPoint(m)
  const { challenge, response } = proof
  const pubNonceG_ = response.mul(G).add( pk.mul(challenge))
  const pubNonceH_ = response.mul(H).add(sig.mul(challenge))
  const challenge_ = hashToScalar(pubNonceG_.toString('hex') + '||' + pubNonceH_.toString('hex'))
  
  return challenge.equals(challenge_)
}

// ---------------------------------------------------------------

function schnorrDecode(data, cb) {
  const [ challengeRaw, responseRaw ] = data.split(' ')
  const challenge = scalar(challengeRaw),
        response  = scalar(responseRaw)

  if (challenge && response)
    cb({ challenge, response })
}

function schnorrEncode({ challenge, response }) {
  return challenge.encodeStr()+' '
       + response.encodeStr()
}

function schnorrSign(sk, m) {
  const nonce = genSk()
  const pubNonce = nonce.mul(G)
  
  const challenge = hashToScalar(pubNonce.toString('hex') + '||' + m)

  return { challenge, response: nonce.sub(sk.mul(challenge)) }
}

function schnorrVerify(pk, m, { challenge, response }) {
  const pubNonce_ = response.mul(G).add(pk.mul(challenge))
  const challenge_ = hashToScalar(pubNonce_.toString('hex') + '||' + m)
  
  return challenge.equals(challenge_)
}

// ---------------------------------------------------------------

function polyEval(constTerm, coeffs, evalPoint) {
  return add(constTerm, ...coeffs.map((c, j) => c.mul(evalPoint.toThe(j))))
}

function secretShare(sk, t, n) {
  const coeffs = [...Array(t-1)].map((_, i) => genSk())
  const shares = [...Array(n)].map((_, i) => polyEval(sk, coeffs, i+1))
  return { shares, coeffs }
}

function interpolate(shares_, x_ = 0) {
  const shares = shares_.reduce((acc, s, i) => { if (s) acc.push([i+1, s]) }, [ ])
  const x = scalar(x_)

  return shares.reduce((sacc, [i_, share]) => {
    const i = scalar(i_)
    const coeff = shares.reduce((acc, [j]) => {
    const j = scalar(j_)
      return acc.mul(x.sub(j).div(i.sub(j))) // acc *= (x-j)/(i-j)
    }, scalar(1))
    
    return sacc.add(share.mul(coeff))
  }, scalar(0))
}

// ---------------------------------------------------------------

function feldmanDeal(epoch, tag, sk, t, broker) {
  t = t||(((broker.n - 1)/3|0) + 1)

  const { shares, coeffs } = secretShare(sk, t, broker.n)
  const skCommit = sk.mul(G)
  const coeffCommits = coeffs.map(c => c.mul(G))
  const commitEnc = skCommit.encodeStr()
    +' '+coeffCommits.map(p => p.encodeStr()).join(' ')
  
  const mFunc = (i) => shares[i].encodeStr()+' '+commitEnc
  broker.send(epoch, tag, mFunc)

  return hashToStr(commitEnc)
}

function feldmanReceive(epoch, tag, sender, t, broker) {
  t = t||(((broker.n - 1)/3|0) + 1)
  const result = defer()

  broker.receiveFrom(epoch, tag, sender, m => {
    const [ shareRaw, skCommitRaw, ...coeffCommitsRaw ] = m.split(' ')
    const share = scalar(shareRaw),
          skCommit = point(skCommitRaw),
          coeffCommits = coeffCommitsRaw.map(p = > point(p))
    
    if (share && skCommit && coeffCommits.every(p => p)) {
      if (share.mul(G).equals(polyEval(skCommit, coeffCommits, broker.thisHostIndex))) {
        const pks = [...Array(broker.n)].map((_, i) => polyEval(skCommit, coeffCommits, i))
        
        result.resolve({ share, pks, pk:skCommit, h:hashToStr(m.split(' ').slice(1).join(' ')) })
      }
    }
  })
}

// ---------------------------------------------------------------

function pedersenCommit(val, mask) {
  return val.mul(G).add(mask.mul(G1))
}

function pedersenVerify(val, mask, commitment) {
  return pedersenCommit(val, mask).equals(commitment)
}

function pedersenZKProve(val, mask) {
  const pk = val.mul(G)
  return { mask, pk, sig:schnorrSign(val, ''), c:pk.add(mask.mul(G1)) }
}

function pedersenZKEncode({ mask, pk, sig, c }) {
  return mask.encodeStr() + ' ' + pk.encodeStr() + ' ' + c.encodeStr() + ' ' + schnorrEncode(sig)
}

function pedersenZKDecode(data, cb) {
  const [ maskRaw, pkRaw, cRaw, ...sigRaw ] = data.split(' ')
  const mask = scalar(maskRaw),
        pk = point(pkRaw),
        c = point(cRaw)
  if (mask && pk && c) {
    schnorrDecode(sigRaw.join(' '), sig => cb({ mask, pk, c, sig }))
  }
}

function pedersenZKVerify(proof) {
  return (proof.pk.add(proof.mask.mul(G1)).equals(proof.c)
       && schnorrVerify(proof.pk, '', proof.sig))
}

// ---------------------------------------------------------------

function feldmanDeal2D(epoch, tag, sk, t, broker) {
  const k = ((broker.n - 1)/3|0) + 1
  t = t||k
  
  const { shares, coeffs } = secretShare(sk, t, broker.n)
  const { subShares, subCoeffs } = shares.map((share, i) => 
  const skCommit = sk.mul(G)
  const coeffCommits = coeffs.map(c => c.mul(G))
  const commitEnc = skCommit.encodeStr()
    +' '+coeffCommits.map(p => p.encodeStr()).join(' ')
  
  const mFunc = (i) => shares[i].encodeStr()+' '+commitEnc
  broker.send(epoch, tag, mFunc)
  
  return hashToStr(commitEnc)
}

// TODO: add polynomial commitments for better communication complexity
function cachinDealPH(epoch, tag, sk, t, broker) {
  const k = ((broker.n - 1)/3|0) + 1
  t = t||k
  
  const skMask = genSk()
  const skCommit = pedersenCommit(sk, skMask)
  const { shares, coeffs } = secretShare(sk, t, broker.n)
  const { maskShares, maskCoeffs } = secretShare(skMask, t, broker.n)
  const coeffCommits = coeffs.map((coeff, i) => pedersenCommit(coeff, maskCoeffs[i]))
  
  const sub = (ss) => ss.map((s, i) => secretShare(s, k, broker.n))
                        .reduce(({ sArrs, cArrs }, { sArr, cArr }) => {
                          sArr.forEach((s, i) => sArrs[i].push(s))
                          cArrs.push(cArr)
                        }, { [...Array(broker.n)].map(_ => [ ]), [ ] })
  // subShares[i][j] = p_j(i) where p_j is a degree (k-1) polynomial with p_j(0) = shares[j]
  // subCoeffs[i][j] = c_ij s.t. p_i = shares[i] + c_i1*x + ... + c_i(k-1)*x^(k-1)
  const { subShares, subCoeffs } = sub(shares)
  const { subMaskShares, subMaskCoeffs } = sub(maskShares)
  const subCoeffCommits = subCoeffs.map((arr, i) => arr.map((coeff, j) => 
                            pedersenCommit(coeff, subMaskCoeffs[i][j])))
  
  const commitEnc = skCommit.encodeStr()
    +'|'+coeffCommits.map(p => p.encodeStr()).join(' ')
    +'|'+subCoeffCommits.map(pA => pA.map(p => p.encodeStr()).join(' ')).join('|')

  const shareEnc = (i) => shares[i].encodeStr()+'|'+maskShares[i].encodeStr()
                     +'|'+subShares[i].map(s => s.encodeStr()).join(' ')
                     +'|'+subMaskShares[i].map(s => s.encodeStr()).join(' ')
  
  const mFunc = (i) => shareEnc(i)+'+'+commitEnc
  broker.send(epoch, tag, mFunc)

  return hashToStr(commitEnc)
}

function cachinReceivePH(epoch, tag, sender, t, broker) {
  const k = ((broker.n - 1)/3|0) + 1
  t = t||k
  const result = defer(), mustRecover = defer()
  
  let share, maskShare, subShares, subMaskShares, skCommit, coeffCommits, subCoeffCommits, h

  broker.receiveFrom(epoch, tag, sender, m => {
    const [ shareStuffRaw, commitStuffRaw ] = m.split('+')
    if (!shareStuffRaw || !commitStuffRaw) return;

    const [ shareRaw, maskShareRaw, subSharesRaw, subMaskSharesRaw ] = shareStuffRaw.split('|')
    const [ skCommitRaw, coeffCommitsRaw, ...subCoeffCommitsRaw ] = commitStuffRaw.split('|')

    if (!shareRaw || !maskShareRaw || !subSharesRaw || !subMaskSharesRaw) return;
    if (!skCommitRaw || !coeffCommitsRaw || !subCoeffCommitsRaw) return;
    
    const subShareRaws = subSharesRaw.split(' ')
    const subMaskShareRaws = subMaskSharesRaw.split(' ')
    
    const coeffCommitRaws = coeffCommitsRaw.split(' ')
    const subCoeffCommitRaws = subCoeffCommitsRaw.map(astr => astr.split(' '))
    
    if (subShareRaws.length !== n || subMaskShareRaws.length !== n ||
        coeffCommitRaws.length !== t || subCoeffCommitRaws.length !== n ||
        !subCoeffCommitRaws.every(a => a.length === k)) return;
    
    share = scalar(shareRaw),
    maskShare = scalar(maskShareRaw),
    subShares = subShareRaws.map(s => scalar(s)),
    subMaskShares = subMaskShareRaws.map(s => scalar(s)),
    skCommit = point(skCommitRaw),
    coeffCommits = coeffCommitRaws.map(p = > point(p)),
    subCoeffCommits = subCoeffCommitRaws.map(a => a.map(p => point(p)))
    
    if (!share || !maskShare || !skCommit || 
        !subShares.every(s => s) || !subMaskShares.every(s => s) ||
        !coeffCommits.every(p => p) || !coeffCommits.every(a => a.every(p => p))) return;
    
    if (pedersenCommit(share, maskShare)
        .equals(polyEval(skCommit, coeffCommits, broker.thisHostIndex))) {
      const shareCommits = [...Array(broker.n)].map((_, i) => polyEval(skCommit, coeffCommits, i))
      
      if (subShares.every((subShare, i) => pedersenCommit(subShare, subMaskShare[i])
          .equals(polyEval(shareCommits[i], subCoeffCommits[i], broker.thisHostIndex)))) {
        h = hashToStr(commitStuffRaw)
        
        broker.broadcast(epoch, tag+'e', h)
        mustRecover.then(([ h_, unrecoveredNodes ]) => {
          if (h !== h_) return;
          
          unrecoveredNodes.forEach(j => 
            broker.sendTo(epoch, tag+'u', j, subShareRaws[j]+' '+subMaskShareRaws[j]+
                                             subCoeffCommits[j].join(' ')))
        }
      }
    }
  })
  
  const hashes = [...Array(broker.n)]
  broker.receive(epoch, tag+'e', (i, h_) => {
    hashes[i] = h_
    let matching = hashes.filter(h__ => h__ === h_)
    if (matching.length >= n-k) {
      mustRecover.resolve([ h_, [...Array(broker.n)].map((_,i) => i).filter(i => !hashes[i]) ])
      broker.broadcast(epoch, tag+'r', h_)
      
      return true
    }
  })
  
  broker.receive(epoch, tag+'r', (i, h_) => {
    
  })
  
  broker.receive(epoch, tag+'u', (i, data) => {
    if (recovered) return true
  })
}

// ---------------------------------------------------------------

function AVSSDeal(epoch, tag, secret, broker) {
  const t = ((broker.n - 1)/3|0) + 1
  
  cachinDealIS(epoch, tag+'b', secret, t, broker)
}

function AVSSReceive(epoch, tag, sender, broker) {
  const t = ((broker.n - 1)/3|0) + 1
  const result = defer()
  let receivedShare = undefined
  
  const receivedEchoes = [...new Array(broker.n)]
  feldmanReceive(epoch, tag+'b', sender, t, broker, receivedShare_ => {
    receivedShare = receivedShare_
    broker.broadcast(epoch, tag+'e', receivedShare.h)
    
    if (receivedEchoes.filter(h => h === m).length >= n-t)
      result.resolve(receivedShare)
  })
  
  broker.receive(epoch, tag+'e', (i, m) => {
    receivedEchoes[i] = m
    
    if (receivedShare && receivedEchoes.filter(h => h === receivedShare.h).length >= n-t)
      result.resolve(receivedShare)
  })
}

// ---------------------------------------------------------------

// Based on Cachin-Kursawe-Shoup threshold signature-based common coin
// using Boldyreva threshold signatures, but rather than verifying the
// shares using a pairing we instead use a Chaum-Pedersen NIZK to prove
// equality of discrete logs. Note this precludes aggregate verification.
function commonCoin(epoch, tag, sk, pks, t, broker) {
  t = t||(((broker.n - 1)/3|0) + 1)
  const result = defer()

  const id = epoch.length+' '+epoch+tag
  broker.broadcast(epoch, tag, chaumPedersenEncode(chaumPefersenProve(sk, id)))
  
  const shares = [...Array(broker.n)]
  let count = 0
  broker.receive(epoch, tag, (i, m) => {
    chaumPedersenDecode(m, (cpProof => {
      if (chaumPedersenVerify(pks[i], id, cpProof)) {
        shares[i] = cpProof.sig
        count++
        if (count >= t) {
          result.resolve(hashToStr(interpolate(shares)))
        }
      }
    })
  })
}

// Slightly modified version of Canetti's common coin that doesn't use
// threshold cryptography. Modifications are:
//   - Uses consistent AVSS instead of full AVSS since we're in the computational
//     setting where we can verify shares.
//   - Instead of sharing n^2 secrets, we just share s[1],..,s[n] and take
//     the (i, j) secret to be F(s[i], j), where F is a key-homomorphic prf.
//   - Most of the protocol is done only once to derive the shared secrets; after
//     that we use F to derive the partially shared random values for each coin flip.
function setupHeavyCommonCoin(epoch, tag, broker) {
  const id = epoch.length+' '+epoch+tag
  const result = defer()

  // Each node deals a secret
  const r = genSk()
  dealCAVSS(epoch, tag+'a'+broker.thisHostIndex, r, broker)
  
  const avss_instances = [...Array(broker.n)].map((_, i) => 
    receiveCAVSS(epoch, tag+'a'+i, i, broker))
  
  const receivedShares = [...Array(broker.n)]
  let C = [ ], G = [ ]
  avss_instances.map((p, i) => p.then(share => {
    
  }))
}

function keyGenSync(epoch, tag, t, broker) {
  
}
