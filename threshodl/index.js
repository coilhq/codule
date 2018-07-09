const EC = require('elliptic').ec
const sha = require('sha.js')
const { randomBytes } = require('crypto')
const BN = require('bn.js')
const HmacDRBG = require('hmac-drbg')

// ---------------------------------------------------------------

const ecc = new EC('secp256k1')
const Fr = BN.red(ecc.curve.redN)

const skLength = 32
const pkLength = 33

function point(val_) {
  if (val_ === undefined) return undefined
  else if (val_ === 0) {
    return point(ecc.curve.pointFromJSON([null, null]))
  } else if (typeof val_ === 'string') {
    return point(Buffer.from(val_.padEnd(val_.length+3-((val_.length-1)&3),'='), 'base64'))
    
  } else if (val_.constructor.toString().startsWith('function Buffer')) {
    if (val_.length !== pkLength || (val_[0] !== 2 && val_[0] !== 3)) return undefined

    try {
      const dec = ecc.curve.decodePoint(val_)
      if (dec.validate()) return point(dec)
    } catch (e) { }

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
      equals:P2 => {
        if (!P2.isPoint) throw "cannot compare a point with a non-point!"
        return (val.eq(P2.val))
      },
      encode:() => Buffer.from(val.encodeCompressed()),
      encodeStr:() => Buffer.from(val.encodeCompressed()).toString('base64').replace(/=/gi,'')
    }

  } else {
    throw "unknown data type converted to point"
  }
}

function scalar(val_) {
  if (val_ === undefined) return undefined
  else if (typeof val_ === 'number' || val_.constructor.toString().startsWith('function Buffer')) {
    try {
      return scalar(new BN(val_).toRed(Fr))
    } catch (e) { }

  } else if (typeof val_ === 'string') {
    return scalar(Buffer.from(val_.padEnd(val_.length+3-((val_.length-1)&3),'='), 'base64'))
    
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
                            : scalar(val.redMul(P2.val))
      },
      div:P2 => {
        if (!P2.isScalar) throw "cannot divide a scalar by a curve point!"
        return scalar(val.redMul(P2.invert().val))
      },
      invert:() => scalar(val.redInvm()),
      negate:() => scalar(val.redNeg()),
      toThe:(P2) => {
        if (!P2.isScalar) throw "cannot exponentiate a scalar to the power of a curve point!"
        return scalar(val.redPow(P2.val.fromRed()))
      },
      equals:P2 => {
        if (!P2.isScalar) throw "cannot compare a scalar with a non-scalar!"
        return (val.eq(P2.val))
      },
      encode:() => val.toBuffer(),
      encodeStr:() => val.toBuffer().toString('base64').replace(/=/gi,'')
    }

  } else {
    throw "unknown data type converted to scalar"
  }
}

function genSk() {
  while (true) {
    const r = new BN(randomBytes(skLength))
    
    if (r.cmpn(0) <= 0 || r.cmp(ecc.curve.n) >= 0)
      continue;
    
    return scalar(r)
  }
}

function hashToStr(m) {
  return sha('sha256').update(m).digest('base64').replace(/=/gi, '')
}

function hashToBuf(m) {
  return sha('sha256').update(m).digest()
}

function sha512_256(m) {
  return sha('sha512').update(m).digest('hex').substr(0, 64)
}

function hashToScalar(m) {
  return scalar(hashToBuf(m))
}

function hashToPoint(m) {
  let buf = Buffer.alloc(pkLength), i = 0, ret

  while (true) {
    let one = hashToStr(i+m)
    buf[0] = (Buffer.from(one.padEnd(one.length+3-((one.length-1)&3),'='), 'base64')[0] % 2) ? 2 : 3
    buf.set(hashToBuf(one+m), 1)

    try {
      ret = ecc.curve.decodePoint(buf)
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

function replaceECStuffWithStrs(obj) {
  if (typeof obj !== 'object') {
    if (typeof obj === 'string') return 'T'+obj
    else if (typeof obj === 'number') return 'N'+obj.toString(36)
    else throw new Error('encoding error: ' + obj)
  } else if (!obj.isPoint && !obj.isScalar) {
    if (!Array.isArray(obj)) throw new Error('encoding error: not an array')
    
    else return obj.map(subObj => replaceECStuffWithStrs(subObj))
  } else {
    if (obj.isPoint) return 'P'+obj.encodeStr()
    else return 'S'+obj.encodeStr()
  }
}

function encodeData(obj) {
  const newObj = Array.isArray(obj) ? obj.slice(0) : (typeof obj === 'object' ? Object.assign({}, obj) : obj)
  return JSON.stringify(replaceECStuffWithStrs(newObj))
}

function unreplaceECStuffWithStrs(obj, props) {
  if (typeof obj === 'string') {
    if (typeof props !== 'string' || props !== obj[0]) throw 'parsing error'
    else if (obj[0] === 'T') return obj.substr(1)
    else if (obj[0] === 'N') return parseInt(obj.substr(1), 36)
    else if (obj[0] === 'P') return point(obj.substr(1))
    else if (obj[0] === 'S') return scalar(obj.substr(1))
    else throw 'parsing error'
  } else if (Array.isArray(obj)) {
    if (obj.length !== props.length) throw 'parsing error'
    else return obj.map((subObj, i) => unreplaceECStuffWithStrs(subObj, props[i]))
  } else {
    throw 'parsing error'
  }
}

function decodeData(data, props, cb) {
  let parsed, fullyParsed
  try {
    parsed = JSON.parse(data)
    fullyParsed = unreplaceECStuffWithStrs(parsed, props)
  } catch (e) { }
  
  cb(fullyParsed)
}

// ---------------------------------------------------------------

function arrayOf(n, cb = () => undefined) {
  return [...Array(n)].map((_, i) => cb(i))
}

function defer() {
  let resolve, reject
  const promise = new Promise((res, rej) => { resolve = res; reject = rej })
  return { resolve, reject, promise, then:cb => promise.then(cb) }
}

// ---------------------------------------------------------------

const G = point(ecc.curve.g)
const G1 = hashToPoint('1')
const G2 = hashToPoint('2')
const G3 = hashToPoint('3')

// ---------------------------------------------------------------

function pathToLeaf(leaf, treeDepth) {
  return arrayOf(treeDepth, i => (leaf >> (treeDepth-1-i)) % 2)
}

function depth(num) {
  let d = 0
  while ((num-1 >> d) > 0) d++
  
  return d
}

function roundUpPow2(num) {
  return (1 << depth(num))
}

function merkleConstruct_(data) {
  const paddedData = data.concat(arrayOf(roundUpPow2(data.length)-data.length, () => ''))
  
  if (data.length > 1) {
    const lnode = merkleConstruct_(paddedData.slice(0, paddedData.length/2)),
          rnode = merkleConstruct_(paddedData.slice(paddedData.length/2, paddedData.length))
    
    return [ 'N'+hashToStr(lnode[0]+' '+rnode[0]), lnode, rnode ]
  } else return [ 'L'+hashToStr(JSON.stringify(data[0])) ]
}

function merkleBranch(tree, depth, leaf) {
  const side = pathToLeaf(leaf, depth)[0]
  if (depth > 0)
    return [ ...merkleBranch(tree[1+side], depth-1, leaf - (side << (depth-1))), tree[2-side][0] ]
  else
    return [ ]
}

function merkleConstruct(data) {
  const tree = merkleConstruct_(data)
  return { root:tree[0], tree, branch:(leaf) => merkleBranch(tree, depth(data.length), leaf) }
}

function merkleBranchVerify(leaf, datum, branch, root) {
  const pathFromLeaf = pathToLeaf(leaf, branch.length).reverse()
  return branch.reduce((acc, sideHash, i) => 'N'+hashToStr(pathFromLeaf[i] ? (sideHash+' '+acc) : (acc+' '+sideHash)), 'L'+hashToStr(JSON.stringify(datum))) === root
}

// ---------------------------------------------------------------

const chaumPedersenDecode = ['P', ['S', 'S']]

function chaumPedersenProve(sk, m) {
  const H = (m.isPoint) ? m : hashToPoint(m)
  const nonce = genSk()
  const pubNonceG = nonce.mul(G)
  const pubNonceH = nonce.mul(H)
  
  const c = hashToScalar(pubNonceG.encodeStr() + '||' + pubNonceH.encodeStr())

  return [ sk.mul(H), [ c, nonce.sub(sk.mul(c)) ] ]
}

function chaumPedersenVerify(pk, m, [ sig, [ c, z ] ]) {
  const H = (m.isPoint) ? m : hashToPoint(m)
  const pubNonceG_ = z.mul(G).add( pk.mul(c))
  const pubNonceH_ = z.mul(H).add(sig.mul(c))
  const c_ = hashToScalar(pubNonceG_.encodeStr() + '||' + pubNonceH_.encodeStr())
  
  return c.equals(c_)
}

// ---------------------------------------------------------------

const chaumPedersenPHDecode = ['P', ['S', 'S', 'S']]

function chaumPedersenPHProve(sk, mask, m) {
  const H = hashToPoint(m)
  const nonce = genSk(), nonce1 = genSk()
  const pubNonceG = nonce.mul(G).add(nonce1.mul(G1))
  const pubNonceH = nonce.mul(H)
  
  const c = hashToScalar(pubNonceG.encodeStr() + '||' + pubNonceH.encodeStr())

  return [ sk.mul(H), [ c, nonce.sub(sk.mul(c)), nonce1.sub(mask.mul(c)) ] ]
}

function chaumPedersenPHVerify(commit, m, [ sig, [ c, z, z1 ] ]) {
  const H = hashToPoint(m)
  const pubNonceG_ = z.mul(G).add(z1.mul(G1)).add(commit.mul(c))
  const pubNonceH_ = z.mul(H).add(sig.mul(c))
  const c_ = hashToScalar(pubNonceG_.encodeStr() + '||' + pubNonceH_.encodeStr())
  
  return c.equals(c_)
}

// ---------------------------------------------------------------

const schnorrDecode = ['S', 'S']

function schnorrSign(sk, m) {
  const nonce = genSk()
  const pubNonce = nonce.mul(G)
  
  const c = hashToScalar(pubNonce.encodeStr() + m)

  return [ c, nonce.sub(sk.mul(c)) ]
}

function schnorrVerify(pk, m, [ c, z ]) {
  const pubNonce_ = z.mul(G).add(pk.mul(c))
  const c_ = hashToScalar(pubNonce_.encodeStr() + m)
  
  return c.equals(c_)
}

// ---------------------------------------------------------------

function pedersenCommit(val, mask) {
  return val.mul(G).add(mask.mul(G1))
}

function pedersenVerify(val, mask, commitment) {
  return pedersenCommit(val, mask).equals(commitment)
}

const pedersenPKDecode = ['P', ['S', schnorrDecode]]

function pedersenPKProve(val, mask) {
  const pk = val.mul(G)
  return [ pk,  [ mask, schnorrSign(val, '') ] ]
}

function pedersenPKVerify([ pk, [ mask, sig ] ], commitment) {
  return (pk.add(mask.mul(G1)).equals(commitment) && schnorrVerify(pk, '', sig))
}

// ---------------------------------------------------------------

function polyEval(constTerm, coeffs, evalPoint) {
  return add(constTerm, ...coeffs.map((c, j) => c.mul(evalPoint.toThe(scalar(j+1)))))
}

function polyEvalPlayer(constTerm, coeffs) {
  return i => polyEval(constTerm, coeffs, scalar(i+1))
}

function secretShare(sk, t, n) {
  const coeffs = arrayOf(t-1, genSk)
  const shares = arrayOf(n, polyEvalPlayer(sk, coeffs))
  return { shares, coeffs }
}

function interpolate(shares_, x_ = 0) {
  const shares = shares_.reduce((acc, s, i) => { if (s) acc.push([i+1, s]); return acc }, [ ])
  const x = scalar(x_)
  let typeOfShares = (shares[0][1].isScalar) ? scalar : point

  return shares.reduce((sacc, [i_, share]) => {
    const i = scalar(i_)
    const coeff = shares.reduce((acc, [j_]) => {
      if (i_ === j_) return acc
      
      const j = scalar(j_)
      return acc.mul(x.sub(j).div(i.sub(j))) // acc *= (x-j)/(i-j)
    }, scalar(1))
    
    return sacc.add(share.mul(coeff))
  }, typeOfShares(0))
}

// ---------------------------------------------------------------

// TODO: add polynomial commitments for better communication complexity
function AVSSPHDeal(tag, sk, broker, reliableBroadcast, t) {
  const n = broker.n, f = (n - 1)/3|0
  t = t||f+1
  
  const skMask = genSk()
  const skCommit = pedersenCommit(sk, skMask)
  const { shares:shares, coeffs:coeffs } = secretShare(sk, t, n)
  const { shares:maskShares, coeffs:maskCoeffs } = secretShare(skMask, t, n)
  const coeffCommits = coeffs.map((coeff, i) => pedersenCommit(coeff, maskCoeffs[i]))
  
  const sub = (ss) => ss.map((s, i) => secretShare(s, f+1, n))
                        .reduce(({ sArrs, cArrs }, { shares, coeffs }) => {
                          shares.forEach((s, i) => sArrs[i].push(s))
                          cArrs.push(coeffs)
                          
                          return { sArrs, cArrs }
                        }, { sArrs:arrayOf(n, () => [ ]), cArrs:[ ] })
  
  // subShares[i][j] = p_j(i) where p_j is a degree (k-1) polynomial with p_j(0) = shares[j]
  // subCoeffs[i][j] = c_ij s.t. p_i = shares[i] + c_i1*x + ... + c_i(k-1)*x^f
  const { sArrs:subShares, cArrs:subCoeffs } = sub(shares)
  const { sArrs:subMaskShares, cArrs:subMaskCoeffs } = sub(maskShares)
  const subCoeffCommits = subCoeffs.map((arr, i) => arr.map((coeff, j) => 
                            pedersenCommit(coeff, subMaskCoeffs[i][j])))

  const mFunc = i => encodeData([ shares[i], maskShares[i], subShares[i], subMaskShares[i],
                                  skCommit, coeffCommits, subCoeffCommits ])
  reliableBroadcast(tag, mFunc, broker)

  return hashToStr(encodeData([ skCommit, coeffCommits, subCoeffCommits ]))
}

function AVSSPHReceive(tag, sender, broker, reliableReceive, t) {
  const n = broker.n, f = (n - 1)/3|0
  t = t||f+1
  const result = defer(), didntEcho = defer(), shouldRecover = defer(), recoveredValue = defer()
  let echoed = false, readied = false, recovered = false
  
  let share, maskShare, subShares, subMaskShares, skCommit, coeffCommits, subCoeffCommits, h

  reliableReceive(tag, sender, broker, m => {
    const ret = defer()
    if (echoed) return true
    
    decodeData(m, ['S', 'S', arrayOf(n, _ => 'S'),
                             arrayOf(n, _ => 'S'), 'P',
                   arrayOf(t-1, _ => 'P'),
                   arrayOf(n, _ => arrayOf(f, _ => 'P'))], 
    ([ share, maskShare, subShares, subMaskShares, skCommit, coeffCommits, subCoeffCommits ]) => {
  
      console.log('o hi mark')
      if (pedersenCommit(share, maskShare)
          .equals(polyEvalPlayer(skCommit, coeffCommits)(broker.thisHostIndex))) {
        const shareCommits = arrayOf(n, polyEvalPlayer(skCommit, coeffCommits))
        console.log('o hi mark deux')
        
        if (subShares.every((subShare, i) => pedersenCommit(subShare, subMaskShares[i])
            .equals(polyEvalPlayer(shareCommits[i], subCoeffCommits[i])(broker.thisHostIndex)))) {
          h = hashToStr(encodeData([skCommit, coeffCommits, subCoeffCommits]))
          console.log('o hi mark dry')
          
          ret.resolve(h)
          echoed = true
          
          didntEcho.then(([ h_, unrecoveredNodes ]) => {
            if (h !== h_) return;
            unrecoveredNodes.forEach(j => broker.sendTo(tag+'u', j, 
                                encodeData([ subShares[j], subMaskShares[j], skCommit,
                                             shareCommits, subCoeffCommits[j] ])))
          })
          
          shouldRecover.then(h_ => {
            if (h === h_) {
              recoveredValue.resolve({ share, maskShare, skCommit, shareCommits })
              recovered = true
            }
          })
        }
      }
    })
    
    return ret.promise
  }, didntEcho)
  .then(h_ => {
    shouldRecover.resolve(h_)
    result.resolve(recoveredValue)
  })
  
  const recoveryData = arrayOf(n)
  broker.receive(tag+'u', (i, data) => {
    if (recovered) return true
    
    decodeData(data, ['S', 'S', 'P',
                       arrayOf(n, _ => 'P'),
                       arrayOf(f, _ => 'P')],
    ([ subShare, subMaskShare, skCommit, shareCommits, subCoeffCommits ]) => {
      const c_ = hashToStr(encodeData([skCommit, shareCommits, subCoeffCommits]))
      recoveryData[i] = { subShare, subMaskShare, c_, tested:false }
      
      shouldRecover.then((h_) => {
        if ((h && h === h_) || recovered) return;
        
        if (pedersenCommit(subShare, subMaskShare)
            .equals(polyEvalPlayer(shareCommits[broker.thisHostIndex], subCoeffCommits)(i))) {
          recoveryData[i].tested = true
          
          let matching = recoveryData.filter(dat => (dat && dat.tested && dat.c_ === c_))
          if (matching.length >= f+1) {
            share = interpolate(recoveryData.map(dat => dat && dat.subShare))
            maskShare = interpolate(recoveryData.map(dat => dat && dat.subMaskShare))
            recoveredValue.resolve({ share, maskShare, skCommit, shareCommits })
            recovered = true
          }
        }
      })
    })
  })
  
  return result
}

// ---------------------------------------------------------------

// Based on the Cachin-Kursawe-Shoup threshold signature common coin
// using Boldyreva threshold signatures, but rather than verifying the
// shares using a pairing we instead use a Chaum-Pedersen NIZK to prove
// equality of discrete logs. Note this precludes aggregate verification.
function setupCommonCoin(tag, broker, sk, pks) {
  return Promise.resolve((tag_) => {
    const n = broker.n, f = (n - 1)/3|0
    const result = defer()

    const id = tag.length+' '+tag+tag_
    broker.broadcast(tag+tag_, 
      chaumPedersenEncode(chaumPefersenProve(sk, id)))
    
    const shares = arrayOf(n)
    let count = 0
    broker.receive(tag+tag_, (i, m) => {
      chaumPedersenDecode(m, cpProof => {
        if (chaumPedersenVerify(pks[i], id, cpProof)) {
          shares[i] = cpProof.sig
          count++
          if (count >= f+1) {
            result.resolve(hashToStr(interpolate(shares)))
          }
        }
      })
    })
    
    return result.promise
  })
}

function setupKeygenProposals(tag, broker, reliableBroadcast, reliableReceive) {
  const n = broker.n, f = (n - 1)/3|0
  const result = defer()

  // Each node deals a secret
  const r = genSk()
  AVSSPHDeal(tag+'a'+broker.thisHostIndex, r, broker, reliableBroadcast)
  
  const AVSSInstances = arrayOf(n, i => 
    AVSSPHReceive(tag+'a'+i, i, broker, reliableReceive))
  
  const pendingAttaches = arrayOf(n, () => [ defer(), defer() ]),
        pendingAttachesFinalized = arrayOf(n, () => [ defer(), defer() ])
        
  const C = [ ], G = [ ]
  let accepted = false, readied = false
  
  function update(arr) {
    arr.forEach(async ([p1, p2]) => {
      const A = await p1
      if (A.every(i => C.includes(i)))
        p2.resolve(A)
    })
  }
  
  
  
  AVSSInstances.forEach(async (p, i) => {
    await p
    
    C.push(i)
    update(pendingAttaches)
    update(pendingAttachesFinalized)
    
    if (!accepted && C.length >= f+1) {
      reliableBroadcast(tag+'c'+broker.thisHostIndex, JSON.stringify(C), broker)
      accepted = true
    }
  })
  
  const attaches = arrayOf(n, i =>
    reliableReceive(tag+'c'+i, i, broker, m => {
      try {
        let A = [...(new Set(JSON.parse(m))).values()]
        if (A.length >= f+1) {
          pendingAttaches[i][0].resolve(A)
        }
      } catch (e) { }
      
      return pendingAttaches[i][1].then(A => JSON.stringify(A))
    }))
  
  let onAddToG_ = () => { }
  attaches.forEach(async (p, i) => {
    const A = JSON.parse(await p)
    pendingAttachesFinalized[i][0].resolve(A)
    
    await pendingAttachesFinalized[i][1]
    
    G.push(i)
    onAddToG_()
    
    if (!readied && G.length >= n-f) {
      result.resolve({
        G,
        As:pendingAttachesFinalized.map(([p1, p2]) => p2),
        shares:AVSSInstances,
        onAddToG: cb => { cb(); cb => onAddToG_ = cb }
      })
      readied = true
    }
  })
  
  return result.promise
}

async function setupKeygenProposalsStable(tag, broker, reliableBroadcast, reliableReceive) {
  const n = broker.n, f = (n - 1)/3|0
  const result = defer()
  
  const pendingReadies = arrayOf(n, () => [ defer(), defer() ]),
        pendingReadiesFinalized = arrayOf(n, () => [ defer(), defer() ]),
        pendingOuters = arrayOf(n, () => [ defer(), defer(), defer() ]),
        pendingOutersFinalized = arrayOf(n, () => [ defer(), defer() ])
  
  pendingOuters.forEach(async ([p1, p2, p3], i) => {
    const O = await p3
    let count = 0
    
    pendingReadiesFinalized.forEach(async ([p1B]) => {
      const B = await p1B
      
      if (B.every(j => O.includes(j))) {
        count++
        if (count >= n-f)
          p1.resolve(O)
      }
    })
  })
  
  
  
  const { G, As, shares, onAddToG } = 
    await setupKeygenProposals(tag, broker, reliableBroadcast, reliableReceive)
  
  reliableBroadcast(tag+'g'+broker.thisHostIndex, JSON.stringify(G), broker)
  
  function update(arr) {
    arr.forEach(async ([p1, p2]) => {
      const A = await p1
      if (A.every(i => G.includes(i)))
        p2.resolve(A)
    })
  }
  
  onAddToG(() => {
    update(pendingReadies)
    update(pendingReadiesFinalized)
    update(pendingOuters)
    update(pendingOutersFinalized)
  })
  
  
  
  const readies = arrayOf(n, i =>
    reliableReceive(tag+'g'+i, i, broker, m => {
      try {
        let B = [...(new Set(JSON.parse(m))).values()]
        if (B.length >= n-f) {
          pendingReadies[i][0].resolve(B)
        }
      } catch (e) { }
      
      return pendingReadies[i][1].then(B => JSON.stringify(B))
    }))
  
  let countB = 0, outerd = false
  readies.forEach(async (p, i) => {
    const B = JSON.parse(await p)
    pendingReadiesFinalized[i][0].resolve(B)
    
    await pendingReadiesFinalized[i][1]
    
    countB++
    if (!outerd && countB >= n-f) {
      reliableBroadcast(tag+'o'+broker.thisHostIndex, JSON.stringify(G), broker)
      outerd = true
    }
  })
  
  const outers = arrayOf(n, i =>
    reliableReceive(tag+'o'+i, i, broker, m => {
      try {
        let O = [...(new Set(JSON.parse(m))).values()]
        if (O.length >= n-f) {
          pendingOuters[i][2].resolve(O)
        }
      } catch (e) { }
      
      return pendingOuters[i][1].then(O => JSON.stringify(O))
    }))
  
  let acceptedOuters = [ ]
  outers.forEach(async (p, i) => {
    const O = JSON.parse(await p)
    pendingOutersFinalized[i][0].resolve(O)
    
    await pendingOutersFinalized[i][1]
    
    acceptedOuters.push(O)
    
    if (acceptedOuters.length >= n-f) {
      const finalZ = acceptedOuters.reduce((acc, Oset) => acc.filter(j => Oset.includes(j))),
            finalG = acceptedOuters.reduce((acc, Oset) => [...new Set([...acc, ...Oset])])
      
      const As_ = await Promise.all(As.map((p,j) => 
        G.includes(j) ? p : Promise.resolve(undefined)))
      const shares_ = await Promise.all(shares.map((p, i) => 
        As_.some(A => (A && A.includes(i))) ? p : Promise.resolve(undefined)))
      
      result.resolve({ Z:finalZ, G:finalG, As:As_, shares:shares_ })
    }
  })
  
  return result.promise
}

// Modified version of Canetti's threshold-cryptography-free common coin.
// Modifications are:
//   - Uses consistent AVSS instead of full AVSS since we're in the computational
//     setting where we can verify shares.
//   - Instead of sharing n^2 secrets, we just share s[1],..,s[n] and take
//     the (i, j) secret to be F(s[i], j), where F is a key-homomorphic prf.
//   - Most of the protocol is done only once to derive the shared secrets; after
//     that we use F to derive the partially shared random values for each coin flip.
//   - A tighter analysis of the overlap of the Z sets reveals that |M|>n/2, so I
//     increased u to n+1 which makes the coin common-random more often.
//     Specifically, Pr[c=1 for all nodes], Pr[c=0 for all nodes] >= 0.36 for n>=4.
//     Credit to Alex Ravsky: https://math.stackexchange.com/a/2442870/207264
//   - Adds a little bit of extra communication at the end to make it so that if
//     any node terminates setup with the support set Z, then Z is contained in G.
//     This allows us to lock G in place so that even if we later add a node to G,
//     we won't need to reconstruct the share corresponding to this node.
async function setupHeavyCommonCoin(tag, broker, reliableBroadcast, reliableReceive) {
  const n = broker.n, f = (n - 1)/3|0
  
  const { Z, G, As, shares:keys }
    = await setupKeygenProposalsStable(tag+'s', broker, reliableBroadcast, reliableReceive)
  
  console.error(keys)
  
  const Akeys = arrayOf(n, i => As[i] && ({
    share: add(...As[i].map(j => keys[j].share)),
    maskShare: add(...As[i].map(j => keys[j].maskShare)),
    skCommit: add(...As[i].map(j => keys[j].skCommit)),
    shareCommits: arrayOf(n, x => add(...As[i].map(j => keys[j].shareCommits[x])))
  }))
  
  function thresholdPRF(i, tag_) {
    const { share, maskShare, skCommit } = Akeys[i]
    const id = skCommit.encodeStr()+' '+i+' '+tag.length+tag+tag_
    return chaumPedersenPHProve(share, maskShare, id)
  }
  
  function verifyPRFShare(i, tag_, sender, PRFShare) {
    const { shareCommits, skCommit } = Akeys[i]
    const id = skCommit.encodeStr()+' '+i+' '+tag.length+tag+tag_
    return chaumPedersenPHVerify(shareCommits[sender], id, PRFShare)
  }
  
  return (tag_) => {
    const result = defer()
    
    const shares = G.reduce((acc, i) => [...acc, [i, encodeData(thresholdPRF(i, tag_))]], [])
    broker.broadcast(tag+tag_, JSON.stringify(shares))
    
    const acceptedCoinShares = arrayOf(n, () => arrayOf(n))
    let count = 0
    broker.receive(tag+tag_, (i, m) => {
      const verifiedShares = arrayOf(n)
      let otherShares
      try {
        otherShares = JSON.parse(m).map(([j, PRFShareRaw]) => {
          decodeData(PRFShareRaw, chaumPedersenPHDecode, PRFShare => {
            if (verifyPRFShare(j, tag_, i, PRFShare)) verifiedShares[j] = PRFShare[0]
          })
        })
      } catch (e) { return }
      
      console.log(verifiedShares)
      
      if (Z.every(j => verifiedShares[j])) {
        verifiedShares.forEach((sig, j) => acceptedCoinShares[j][i] = sig)
        count++
      }
      
      if (count >= f+1) {
        result.resolve(Z.map(j => interpolate(acceptedCoinShares[j]))
                       .every(sig => !(hashToScalar(sig.encodeStr()).val.modn(n+1) === 0)))
        console.log(Z.map(j => interpolate(acceptedCoinShares[j]))
                       .map(sig => hashToScalar(sig.encodeStr()).val.modn(n+1)))
      }
    })
    
    return result.promise
  }
}

async function keyGenAsync(tag, broker, reliableBroadcast, reliableReceive, setupConsensus) {
  const n = broker.n, f = (n-1)/3|0
  const result = defer()
  
  const proposals =
    setupKeygenProposals(tag+'g', broker, reliableBroadcast, reliableReceive)
  
  const consensusSetup = setupConsensus(tag+'c', broker)
  
  const [ { G, As, shares }, consensus ] =  await Promise.all([ proposals, consensusSetup ])
  consensus.vote(G)
  
  const G_ = await consensus.result
  const i = G_.sort()[0]
  
  const A = await As[i]
  const shares_ = await Promise.all(shares.filter((_, i) => A.includes(i)))
  
  share = add(...shares_.map(s => s.share)),
  maskShare = add(...shares_.map(s => s.maskShare)),
  skCommit = add(...shares_.map(s => s.skCommit)),
  shareCommits = arrayOf(n, x => add(...shares_.map(s => s.shareCommits[x])))
  
  broker.broadcast(tag+'f', encodeData(pedersenPKProve(share, maskShare)))
  
  const pks = arrayOf(n)
  let count = 0
  broker.receive(tag+'f', (i, m) => {
    decodeData(m, pedersenPKDecode, ([ pk, proof ]) => {
      if (pedersenPKVerify([ pk, proof ], shareCommits[i])) {
        pks[i] = pk
        count++
        
        if (count >= f+1) {
          const sharePKs = arrayOf(n, i => pks[i]||interpolate(pks, i+1))
          const pk = interpolate(pks)
          
          result.resolve({ share, sharePKs, pk })
        }
      }
    })
  })
  
  return result.promise
}

async function thresholdECDSA(tag, broker, sk, pks, msg, keyGen) {
  const n = broker.n, f = (n-1)/3|0
  
  function truncateToN(msg, truncOnly) {
    const delta = msg.byteLength() * 8 - ecc.curve.n.bitLength()
    if (delta > 0)
      msg = msg.ushrn(delta)
    if (!truncOnly && msg.cmp(ecc.curve.n) >= 0)
      return msg.sub(ecc.curve.n)
    else
      return msg
  }
  
  function toDER(r, s) {
    r = r.toArray()
    s = s.toArray()
    
    function constructLength(arr, len) {
      if (len < 0x80) {
        arr.push(len)
        return
      }
      
      let octets = 1 + (Math.log(len) / Math.LN2 >>> 3)
      arr.push(octets | 0x80)
      while (--octets) {
        arr.push((len >>> (octets << 3)) & 0xff)
      }
      
      arr.push(len)
    }

    function rmPadding(buf) {
      let i = 0
      const len = buf.length - 1
      while (!buf[i] && !(buf[i + 1] & 0x80) && i < len) {
        i++
      }
      if (i === 0) {
        return buf
      }
      return buf.slice(i)
    }

    // Pad values
    if (r[0] & 0x80)
      r = [ 0 ].concat(r)
    // Pad values
    if (s[0] & 0x80)
      s = [ 0 ].concat(s)

    r = rmPadding(r)
    s = rmPadding(s)

    while (!s[0] && !(s[1] & 0x80)) {
      s = s.slice(1)
    }
    
    let arr = [ 0x02 ]
    constructLength(arr, r.length)
    arr = arr.concat(r)
    arr.push(0x02)
    constructLength(arr, s.length)
    const backHalf = arr.concat(s)
    let res = [ 0x30 ]
    constructLength(res, backHalf.length)
    res = res.concat(backHalf)
    return Buffer.from(res).toString('hex')
  }
  
  const msgHash = scalar(truncateToN(new BN(sha512_256(msg), 16)))

  // Zero-extend key to provide enough entropy
  const bytes = ecc.curve.n.byteLength()
  let bkey = sk.val.toArray('be', bytes)

  // Zero-extend nonce to have the same byte size as N
  const nonce = msgHash.val.toArray('be', bytes)

  // Number of bytes to generate
  const ns1 = ecc.curve.n.sub(new BN(1));

  for (let iter = 0; true; iter++) {
    // Computes kInv by generating shares of a second random secret b, then revealing k*b
    // and applying the linear function x->x/(k*b) to our share of b.
    const kAndKInv = defer()
    {
      const [{ share:k, sharePKs:kSharePKs, pk:kPK }, { share:b, sharePKs:bSharePKs, pk:bPK }] =
        await Promise.all([ keyGen(tag+'n'+iter+'_', broker), keyGen(tag+'b'+iter+'_', broker) ])
      
      const kbShare = k.mul(b), proof = chaumPedersenProve(k, bSharePKs[broker.thisHostIndex])
      broker.broadcast(tag+'r'+iter, encodeData([ kbShare, proof ]))
      
      const kbShares = arrayOf(n)
      let count = 0, finished = false
      broker.receive(tag+'r'+iter, (i, m) => {
        if (finished) return;
        console.error('received r'+i+': ' + m)
        decodeData(m, ['S', chaumPedersenDecode], ([ kbShare, proof ]) => {
          if (chaumPedersenVerify(kSharePKs[i], bSharePKs[i], proof) &&
              proof[0].equals(kbShare.mul(G))) {
            console.error('verified r'+i+': ' + m)
            kbShares[i] = kbShare
            count++
            
            if (count === 2*f+1) {
              const kb = interpolate(kbShares)
              if (kb.val.fromRed().cmpn(0) === 0) kAndKInv.resolve([ ])
              else kAndKInv.resolve([ k, b.div(kb), bSharePKs.map(pk => pk.div(kb)), kPK ])
              finished = true
            }
          }
        })
      })
    }
    
    let [ k, kInv, kInvSharePKs, kPK ] = await kAndKInv.promise
    console.error('constructed k')
    
    if (!k) continue;

    const kpX = kPK.val.getX()
    const r = scalar(kpX.umod(ecc.curve.n))
    if (r.val.cmpn(0) === 0) continue;
    
    const sShare = kInv.mul(r.mul(sk).add(msgHash))
    
    const sp = defer()
    {
      const proof = chaumPedersenProve(sk, kInvSharePKs[broker.thisHostIndex])
      broker.broadcast(tag+'s'+iter, encodeData([ sShare, proof ]))
      
      const sShares = arrayOf(n)
      let count = 0, finished = false
      broker.receive(tag+'s'+iter, (i, m) => {
        if (finished) return;
        console.error('received s'+i+': ' + m)
        decodeData(m, ['S', chaumPedersenDecode], ([ sShare, proof ]) => {
          if (chaumPedersenVerify(pks[i], kInvSharePKs[i], proof) &&
              proof[0].mul(r).add(kInvSharePKs[i].mul(msgHash))
                .equals(sShare.mul(G))) {
            console.error('verified s'+i+': ' + m)
            sShares[i] = sShare
            count++
            
            if (count >= 2*f+1) {
              sp.resolve(interpolate(sShares))
              finished = true
            }
          }
        })
      })
    }
    
    let s = (await sp.promise).val.fromRed()
    console.error('constructed s')
    
    if (s.cmpn(0) === 0)
      continue;

    let recoveryParam = (kPK.val.getY().isOdd() ? 1 : 0) |
                        (kpX.cmp(r) !== 0 ? 2 : 0)

    // Use complement of `s`, if it is > `n / 2`
    if (s.cmp(ecc.nh) > 0) {
      s = ecc.curve.n.sub(s)
      recoveryParam ^= 1
    }

    console.error(r.val.fromRed())
    console.error(s)

    return toDER(r.val.fromRed(), s)
  }
}

module.exports = {
  setupHeavyCommonCoin,
  setupCommonCoin,
  keyGenAsync,
  thresholdECDSA
}
