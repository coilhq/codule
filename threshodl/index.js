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
  return scalar(randomBytes(skLength))
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
    else throw 'encoding error'
  } else if (!obj.isPoint && !obj.isScalar) {
    if (!Array.isArray(obj)) throw 'encoding error'
    
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
function AVSSPHDeal(epoch, tag, sk, broker, reliableBroadcast, t) {
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
  reliableBroadcast(epoch, tag, mFunc, broker)

  return hashToStr(encodeData([ skCommit, coeffCommits, subCoeffCommits ]))
}

function AVSSPHReceive(epoch, tag, sender, broker, reliableReceive, t) {
  console.log('started from the bottom now we still at the bottom')
  const n = broker.n, f = (n - 1)/3|0
  t = t||f+1
  const result = defer(), didntEcho = defer(), shouldRecover = defer(), recoveredValue = defer()
  let echoed = false, readied = false
  
  let share, maskShare, subShares, subMaskShares, skCommit, coeffCommits, subCoeffCommits, h

  reliableReceive(epoch, tag, sender, broker, (m, ret) => {
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
            unrecoveredNodes.forEach(j => broker.sendTo(epoch, tag+'u', j, 
                                encodeData([ subShares[j], subMaskShares[j], skCommit,
                                             shareCommits, subCoeffCommits[j] ])))
          })
          
          recoveredValue.resolve({ share, maskShare, skCommit, shareCommits })
        }
      }
    })
  }, didntEcho)
  .then(() => {
    shouldRecover.resolve()
    result.resolve(recoveredValue)
  })
  
  const recoveryData = arrayOf(n)
  broker.receive(epoch, tag+'u', (i, data) => {
    if (recovered) return true
    
    decodeData(data, ['S', 'S', 'P',
                       arrayOf(n, _ => 'P'),
                       arrayOf(f, _ => 'P')],
    ([ subShare, subMaskShare, skCommit, shareCommits, subCoeffCommits ]) => {
      const c_ = hashToStr(encodeData([skCommit, coeffCommits, subCoeffCommits]))
      recoveryData[i] = { subShare, subMaskShare, c_, tested:false }
      
      shouldRecover.then(() => {
        if (recovered) return;
        
        if (pedersenCommit(subShare, subMaskShare)
            .equals(polyEvalPlayer(shareCommits[broker.thisHostIndex], subCoeffCommits)(i))) {
          recoveryData[i].tested = true
          
          let matching = recoveryData.filter(dat => (dat.tested && dat.c_ === c_))
          if (matching.length >= f+1) {
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
function setupCommonCoin(epoch, tag, sk, pks, broker) {
  return Promise.resolve((tag_) => {
    const n = broker.n, f = (n - 1)/3|0
    const result = defer()

    const id = epoch.length+' '+tag.length+' '+epoch+tag+tag_
    broker.broadcast(epoch, tag.length+' '+tag+tag_, 
      chaumPedersenEncode(chaumPefersenProve(sk, id)))
    
    const shares = arrayOf(n)
    let count = 0
    broker.receive(epoch, tag.length+' '+tag+tag_, (i, m) => {
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
    
    return result
  })
}

function setupKeygenProposals(epoch, tag, broker, reliableBroadcast, reliableReceive) {
  const n = broker.n, f = (n - 1)/3|0
  const result = defer()

  // Each node deals a secret
  const r = genSk()
  AVSSPHDeal(epoch, tag+'a'+broker.thisHostIndex, r, broker, reliableBroadcast)
  
  const AVSSInstances = arrayOf(n, i => 
    AVSSPHReceive(epoch, tag+'a'+i, i, broker, reliableReceive))
  
  const receivedShares = arrayOf(n), receivedAttaches = arrayOf(n),
        pendingAttaches = arrayOf(n, () => [ ]),
        pendingAttachesFinalized = arrayOf(n, () => [ ])
        
  const C = [ ], G = [ ]
  let accepted = false, readied = false
  
  function updateAttaches() { pendingAttaches.forEach(([A, Ap]) => {
    if (A && A.every(j => C.includes(j)))
      Ap.resolve(JSON.stringify(A))
  }) }
  
  function updateAttachesFinalized() { pendingAttachesFinalized.forEach(([A, Ap]) => {
    if (A && A.every(j => C.includes(j)))
      Ap.resolve()
  }) }
  
  
  
  AVSSInstances.forEach((p, i) => p.then(shareAndCommits => {
    C.push(i)
    updateAttaches()
    updateAttachesFinalized()
    
    receivedShares[i] = shareAndCommits
    if (!accepted && C.length >= f+1) {
      reliableBroadcast(epoch, tag+'c'+broker.thisHostIndex, JSON.stringify(C), broker)
      accepted = true
    }
  }))
  
  const attaches = arrayOf(n, i =>
    reliableReceive(epoch, tag+'c'+i, i, broker, (m, ret) => {
      if (pendingAttaches[i][0]) return;
      try {
        let A = [...(new Set(JSON.parse(m))).values()]
        if (A.length >= f+1) {
          pendingAttaches[i] = [A, ret]
          updateAttaches()
        }
      } catch (e) { }
    }))
  
  attaches.forEach((p, i) => p.then(Araw => {
    const A = JSON.parse(Araw)
    pendingAttachesFinalized[i] = [A, defer()]
    updateAttachesFinalized()
    
    pendingAttachesFinalized[i][1].then(() => {
      G.push(i)
      updateReadies()
      updateOuters()
      
      if (!readied && G.length >= n-f) {
        result.resolve({ G, A:(i) => (As[i]||[])[0], shares:AVSSInstances })
        readied = true
      }
    })
  }))
  
  return result.promise
}

function setupKeygenProposalsStable(epoch, tag, broker, reliableBroadcast, reliableReceive) {
  const n = broker.n, f = (n - 1)/3|0
  const result = defer()
  
  const pendingReadies = arrayOf(n, () => [ ]),
        pendingReadiesFinalized = arrayOf(n, () => [ ]),
        pendingOuters = arrayOf(n, () => [ ])
        
  let G, A, shares
  
  function updateReadies() { pendingReadies.forEach(([B, Bp]) => {
    if (B && B.every(j => G.includes(j)))
      Bp.resolve(JSON.stringify(B))
  }) }
  
  function updateOuters() { pendingOuters.forEach(([O, Op]) => {
    if (O && O.every(j => G.includes(j)) &&
        pendingReadiesFinalized.filter(B => B.every(j => O.includes(j))).length >= n-f)
      Op.resolve(JSON.stringify(O))
  }) }
  
  
  
  setupKeygenProposals(epoch, tag, broker, reliableBroadcast, reliableReceive)
    .then({ G_, A_, shares_ } => {
    G = G_; A = A_; shares = shares_
    reliableBroadcast(epoch, tag+'g'+broker.thisHostIndex, JSON.stringify(G), broker)
  })
  
  const readies = arrayOf(n, i =>
    reliableReceive(epoch, tag+'g'+i, i, broker, (m, ret) => {
      if (pendingReadies[i][0]) return;
      try {
        let B = [...(new Set(JSON.parse(m))).values()]
        if (B.length >= n-f) {
          pendingReadies[i] = [B, ret]
          updateReadies()
        }
      } catch (e) { }
    }))
  
  let countG = 0, outerd = false
  readies.forEach((p, i) => p.then(Braw => {
    const B = JSON.parse(Braw)
    
    pendingReadiesFinalized[i] = B
    updateOuters()
    
    countG++
    if (!outerd && countG >= n-f) {
      reliableBroadcast(epoch, tag+'o'+broker.thisHostIndex, JSON.stringify(G), broker)
      outerd = true
    }
  }))
  
  const outers = arrayOf(n, i =>
    reliableReceive(epoch, tag+'o'+i, i, broker, (m, ret) => {
      if (pendingOuters[i][0]) return;
      try {
        let O = [...(new Set(JSON.parse(m))).values()]
        if (O.length >= n-f) {
          pendingOuters[i] = [O, ret]
          updateOuters()
        }
      } catch (e) { }
    }))
  
  let acceptedOuters = [ ]
  outers.forEach((p, i) => p.then(Oraw => {
    const O = JSON.parse(Oraw)
    acceptedOuters.push(O)
    
    if (acceptedOuters.length >= n-f) {
      const finalZ = acceptedOuters.reduce((acc, Oset) => acc.filter(j => Oset.includes(j))),
            finalG = acceptedOuters.reduce((acc, Oset) => [...new Set([...acc, ...Oset])])
      
      Promise.all(shares.map((p, i) => 
        (finalG.some(j => A(j).includes(i))) ? p : Promise.resolve(undefined)))
        .then(shares => {
        result.resolve({ Z:finalZ, G:finalG, As:arrayOf(n, i => A(i)), shares })
      })
    }
  }))
  
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
function setupHeavyCommonCoin(epoch, tag, broker, reliableBroadcast, reliableReceive) {
  const n = broker.n, f = (n - 1)/3|0
  
  return setupKeygenProposals(epoch, tag+'s', broker, reliableBroadcast, reliableReceive)
    .then(({ Z, G, As, shares:keys }) => {
    const Akeys = arrayOf(n, i => (!G.includes(i)) ? undefined : ({
      share: add(...As[i].map(j => keys[j].share)),
      maskShare: add(...As[i].map(j => keys[j].maskShare)),
      skCommit: add(...As[i].map(j => keys[j].skCommit)),
      shareCommits: arrayOf(n, x => add(...As[i].map(j => keys[j].shareCommits[x])))
    }))
    
    function thresholdPRF(i, tag_) {
      const { share, maskShare, skCommit } = Akeys[i]
      const id = skCommit.encodeStr()+' '+i+' '+epoch.length+' '+tag.length+epoch+tag+tag_
      return chaumPedersenPHProve(share, maskShare, id)
    }
    
    function verifyPRFShare(i, tag_, sender, PRFShare) {
      const { shareCommits, skCommit } = Akeys[i]
      const id = skCommit.encodeStr()+' '+i+' '+epoch.length+' '+tag.length+epoch+tag+tag_
      return chaumPedersenPHVerify(shareCommits[sender], id, PRFShare)
    }
    
    return {
      flipCoin: (tag_) => {
        const result_ = defer()
        
        const shares = G.reduce((acc, i) => [...acc, [i, encodeData(thresholdPRF(i, tag_))]], [])
        broker.broadcast(epoch, tag.length+'_'+tag+tag_, JSON.stringify(shares))
        
        const acceptedCoinShares = arrayOf(n, () => arrayOf(n))
        let count = 0
        broker.receive(epoch, tag.length+'_'+tag+tag_, (i, m) => {
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
            result_.resolve(Z.map(j => interpolate(acceptedCoinShares[j]))
                           .every(sig => !(hashToScalar(sig.encodeStr()).val.modn(n+1) === 0)))
            console.log(Z.map(j => interpolate(acceptedCoinShares[j]))
                           .map(sig => hashToScalar(sig.encodeStr()).val.modn(n+1)))
          }
        })
        
        return result_
      }
    }
  })
}

function keyGenAsync(epoch, tag, broker, reliableBroadcast, reliableReceive, setupConsensus) {
  const thresholdShare = defer(), result = defer()
  
  const proposals =
    setupKeygenProposals(epoch, tag+'g', broker, reliableBroadcast, reliableReceive)
  
  const consensus = setupConsensus(epoch, tag+'c', broker)
  
  Promise.all(proposals, consensus)
    .then(([ { G, A, shares }, consensus ]) => {
    consensus.vote(G)
    consensus.then(G_ => {
      const i = G_.sort()[0]
      thresholdShare.resolve({
        share: add(...As[i].map(j => shares[j].share)),
        maskShare: add(...As[i].map(j => shares[j].maskShare)),
        skCommit: add(...As[i].map(j => shares[j].skCommit)),
        shareCommits: arrayOf(n, x => add(...As[i].map(j => shares[j].shareCommits[x])))
      })
    })
  })
  
  thresholdShare.then(({ share, maskShare, skCommit, shareCommits }) => {
    broker.broadcast(epoch, tag+'f', encodeData(pedersenPKProve(share, maskShare)))
    
    const pks = arrayOf(n)
    let count = 0
    broker.receive(epoch, tag+'f', (i, m) => {
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
  })
  
  return result
}

function thresholdECDSA(epoch, tag, broker, thresholdShare, m, keyGen) {
  function truncateToN(msg, truncOnly) {
    const delta = msg.byteLength() * 8 - e.n.bitLength()
    if (delta > 0)
      msg = msg.ushrn(delta)
    if (!truncOnly && msg.cmp(ecc.curve.n) >= 0)
      return msg.sub(ecc.curve.n)
    else
      return msg
  }
  
  function toDER(r, s) {
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
  
  async function sign(msg, sk) {
    const msgHash = truncateToN(new BN(sha512_256(msg), 16))

    // Zero-extend key to provide enough entropy
    const bytes = ecc.curve.n.byteLength()
    let bkey = sk.toArray('be', bytes)

    // Zero-extend nonce to have the same byte size as N
    const nonce = msgHash.toArray('be', bytes)

    // Instantiate Hmac_DRBG
    const drbg = new HmacDRBG({
      hash: ecc.curve.hash,
      entropy: bkey,
      nonce: nonce,
      persEnc: 'utf8'
    })

    // Number of bytes to generate
    const ns1 = ecc.curve.n.sub(new BN(1));

    for (let iter = 0; true; iter++) {
      // Computes kInv by generating shares of a second random secret b, then revealing k*b
      // and applying the linear function x->x/(k*b) to our share of b.
      let [ k, kInv ] = await
        Promise.all([ keyGen(epoch, tag+'n'+iter+'_'), keyGen(epoch, tag+'b'+iter+'_') ])
        .then(([{ share:k, sharePKs:kSharePKs, pk:kPK },
               { share:b, sharePKs:bSharePKs, pk:bPK }]) => {
        const result = defer()
        const kbShare = k.mul(b), proof = chaumPedersenProve(k, bSharePKs[broker.thisHostIndex])
        broker.broadcast(epoch, tag+'r'+iter, encodeData([ kbShare, proof ]))
        
        const kbShares = arrayOf(n)
        let count = 0
        broker.receive(epoch, tag+'r'+iter, (i, m) => {
          decodeData(m, ['S', chaumPedersenDecode], ([ kbShare, proof ]) => {
            if (chaumPedersenVerify(kSharePKs[i], bSharePKs[i], proof) &&
                proof[0].equals(kbShare.mul(G))) {
              kbShares[i] = kbShare
              count++
              
              if (count >= 2*f+1) {
                result.resolve([ k, b.div(interpolate(kbShares)) ])
              }
            }
          })
        })
        
        return result
      })
      
      k = k.val.fromRed()
      kInv = kInv.val.fromRed()
      
      if (k.cmpn(1) <= 0 || k.cmp(ns1) >= 0)
        continue;

      const kp = kPK
      if (kp.isInfinity())
        continue;

      const kpX = kp.getX()
      const r = kpX.umod(ecc.curve.n)
      if (r.cmpn(0) === 0)
        continue;

      let s = kInv.mul(r.mul(sk).iadd(msgHash))
      s = s.umod(ecc.curve.n)
      if (s.cmpn(0) === 0)
        continue;

      let recoveryParam = (kp.getY().isOdd() ? 1 : 0) |
                          (kpX.cmp(r) !== 0 ? 2 : 0)

      // Use complement of `s`, if it is > `n / 2`
      if (s.cmp(ecc.curve.nh) > 0) {
        s = ecc.curve.n.sub(s)
        recoveryParam ^= 1
      }

      return toDer(r, s)
    }
  }
}

module.exports = {
  setupHeavyCommonCoin,
  setupCommonCoin,
  keyGenAsync
}
