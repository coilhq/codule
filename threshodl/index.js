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
  if (val_ === undefined) return undefined
  else if (typeof val_ === 'string') {
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
        return scalar(val.redPow(P2))
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
  return sha('sha256').update(m).digest('base64')
}

function hashToBuf(m) {
  return Buffer.from(hashToStr(m), 'base64')
}

function hashToScalar(m) {
  return scalar(hashToBuf(m))
}

// NOT sidechannel resistant - do not use to hash secrets
function hashToPoint(m) {
  let buf = Buffer.alloc(pkLength), i = 0, ret

  while (true) {
    let one = hashToStr(i+m)
    buf[0] = (Buffer.from(one, 'base64')[0] % 2) ? 2 : 3
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
    return ['X', obj]
  } else if (!obj.isPoint && !obj.isScalar) {
    const newObj = obj
    for (let key in obj) {
      newObj[key] = replaceECStuffWithStrs(obj[key])
    }
    
    return newObj
  } else {
    return (obj.isPoint) ? ['P', obj.encodeStr()] : ['S', obj.encodeStr()]
  }
}

function encodeData(data) {
  return JSON.stringify(replaceECStuffWithStrs(data))
}

function unreplaceECStuffWithStrs(obj, prefix, props) {
  if (typeof obj !== 'object') {
    throw 'parsing error'
  } else if (obj[0] === 'X') {
    if (obj.length === 2 && props.length === 1 && props[0][1] === 'X') return obj[1]
  } else if (obj[0] === 'P') {
    if (obj.length === 2 && props.length === 1 && props[0][1] === 'P') return point(obj[1])
  } else if (obj[0] === 'S') {
    if (obj.length === 2 && props.length === 1 && props[0][1] === 'S') return scalar(obj[1])
  } else {
    const newObj = obj
    for (let key in obj) {
      const subPrefix = (prefix === '') ? key : prefix+'.'+key
      const subProps = props.filter(prop => prop[0].startsWith(subPrefix))
      if (subProps.length === 0) throw 'parsing error'
      
      newObj[key] = unreplaceECStuffWithStrs(obj[key], subPrefix, subProps)
      if (newObj[key] === undefined) throw 'parsing error'
    }
    
    return newObj
  }
}

function decodeData(data, props, cb) {
  try {
    let parsed = unreplaceECStuffWithStrs(JSON.parse(data), '', props)
    if (props.every(prop => prop[0].split('.').reduce((child, key) => child[key], parsed))) cb(parsed)
  } catch (e) { }
}

function concatProps(prefix, subProps) {
  return (prefix === '') ? subProps : subProps.map(prop => [ prefix+'.'+prop[0], prop[1] ])
}






// ---------------------------------------------------------------

const G = point(ecc.curve.g)
const G1 = hashToPoint('1')
const G2 = hashToPoint('2')
const G3 = hashToPoint('3')

// ---------------------------------------------------------------

function pathToLeaf(leaf, treeDepth) {
  return [...Array(treeDepth)].map((_, i) => (leaf >> (treeDepth-1-i)) % 2)
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
  const paddedData = data.concat([...Array(roundUpPow2(data.length)-data.length)].map(() => ''))
  
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

const chaumPedersenDecode = [['c', 'S'], ['z', 'S'], ['sig', 'P']]

function chaumPedersenProve(sk, m) {
  const H = hashToPoint(m)
  const nonce = genSk()
  const pubNonceG = nonce.mul(G)
  const pubNonceH = nonce.mul(H)
  
  const c = hashToScalar(pubNonceG.encodeStr() + '||' + pubNonceH.encodeStr())

  return { c, z:nonce.sub(sk.mul(challenge)), sig:sk.mul(H) }
}

function chaumPedersenVerify(pk, m, { c, z, sig }) {
  const H = hashToPoint(m)
  const pubNonceG_ = z.mul(G).add( pk.mul(c))
  const pubNonceH_ = z.mul(H).add(sig.mul(c))
  const c_ = hashToScalar(pubNonceG_.encodeStr() + '||' + pubNonceH_.encodeStr())
  
  return c.equals(c_)
}

// ---------------------------------------------------------------

const schnorrDecode = [['c', 'S'], ['z', 'S']]

function schnorrSign(sk, m) {
  const nonce = genSk()
  const pubNonce = nonce.mul(G)
  
  const c = hashToScalar(pubNonce.encodeStr() + m)

  return { c, z: nonce.sub(sk.mul(c)) }
}

function schnorrVerify(pk, m, { challenge, response }) {
  const pubNonce_ = response.mul(G).add(pk.mul(challenge))
  const c_ = hashToScalar(pubNonce_.encodeStr() + '||' + m)
  
  return c.equals(c_)
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

function feldmanDeal(epoch, tag, sk, broker, t) {
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

function feldmanReceive(epoch, tag, sender, broker, t) {
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

const pedersenZKDecode = [['mask', 'S'], ['pk', 'P'], ['c', 'S'], concatProps('sig', schnorrDecode)]

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

function pedersenZKVerify(proof) {
  return (proof.pk.add(proof.mask.mul(G1)).equals(proof.c)
       && schnorrVerify(proof.pk, '', proof.sig))
}

// ---------------------------------------------------------------

// TODO: add polynomial commitments for better communication complexity
function AVSSPHDeal(epoch, tag, sk, broker, reliableBroadcast, t) {
  const f = (broker.n - 1)/3|0
  t = t||f+1
  
  const skMask = genSk()
  const skCommit = pedersenCommit(sk, skMask)
  const { shares, coeffs } = secretShare(sk, t, broker.n)
  const { maskShares, maskCoeffs } = secretShare(skMask, t, broker.n)
  const coeffCommits = coeffs.map((coeff, i) => pedersenCommit(coeff, maskCoeffs[i]))
  
  const sub = (ss) => ss.map((s, i) => secretShare(s, f+1, broker.n))
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
  reliableBroadcast(epoch, tag, mFunc, broker)

  return hashToStr(commitEnc)
}

function AVSSPHReceive(epoch, tag, sender, broker, reliableReceive, t) {
  const f = (broker.n - 1)/3|0
  t = t||f+1
  const result = defer(), mustRecover = defer(), shouldRecover = defer(), recoveredValue = defer()
  let echoed = false, readied = false
  
  let share, maskShare, subShares, subMaskShares, skCommit, coeffCommits, subCoeffCommits, h

  broker.receiveFrom(epoch, tag+'i', sender, m => {
    if (echoed) return true
    try {
      const [ shareStuffRaw, commitStuffRaw ] = m.split('+')

      const [ [share], [maskShare], subShares, subMaskShares ] = shareStuffRaw.split('|').map(a => a.split(' ')).map(a => a.map(s => scalar(s)))
      const [ [skCommit], coeffCommits, ...subCoeffCommits ] = commitStuffRaw.split('|').map(a => a.split(' ')).map(a => a.map(p => point(p)))
      
      if (subShares.length !== n || subMaskShares.length !== n ||
          coeffCommits.length !== t-1 || subCoeffCommits.length !== n ||
          !subCoeffCommits.every(a => a.length === f)) return;
      
      if (!share || !maskShare || !skCommit || 
          !subShares.every(s => s) || !subMaskShares.every(s => s) ||
          !coeffCommits.every(p => p) || !coeffCommits.every(a => a.every(p => p))) return;
      
      if (pedersenCommit(share, maskShare)
          .equals(polyEval(skCommit, coeffCommits, broker.thisHostIndex))) {
        // TODO: investigate if this can be made faster by multiplying by a random polynomial and checking
        // for a few nonzero coeffs
        const shareCommits = [...Array(broker.n)].map((_, i) => polyEval(skCommit, coeffCommits, i))
        
        if (subShares.every((subShare, i) => pedersenCommit(subShare, subMaskShare[i])
            .equals(polyEval(shareCommits[i], subCoeffCommits[i], broker.thisHostIndex)))) {
          h = hashToStr(commitStuffRaw)
          
          broker.broadcast(epoch, tag+'e', h)
          echoed = true
          mustRecover.then(([ h_, unrecoveredNodes ]) => {
            if (h !== h_) return;
            
            unrecoveredNodes.forEach(j => 
              broker.sendTo(epoch, tag+'u', j, subShareRaws[j]+'|'+subMaskShareRaws[j]+'|'+skCommitRaw+'|'
                                               shareCommits.map(c => c.encodeStr()).join(' ')+'|'+subCoeffCommitsRaw[j]))
          }
          
          recoveredValue.resolve({ share, maskShare, skCommit, shareCommits })
        }
      }
    } catch (e) {
    
    }
  })
  
  const hashes = [...Array(broker.n)]
  broker.receive(epoch, tag+'e', (i, h_) => {
    hashes[i] = h_
    let matching = hashes.filter(h__ => h__ === h_)
    if (matching.length >= n-f) {
      mustRecover.resolve([ h_, [...Array(broker.n)].map((_,i) => i).filter(i => !hashes[i]) ])
      if (!readied) broker.broadcast(epoch, tag+'r', h_)
      readied = true
      
      return true
    }
  })
  
  const rhashes = [...Array(broker.n)]
  broker.receive(epoch, tag+'r', (i, h_) => {
    hashes[i] = h_
    let matching = hashes.filter(h__ => h__ === h_)
    if (matching.length >= f+1 && !readied) {
      broker.broadcast(epoch, tag+'r', h_)
      readied = true
    }
    if (matching.length >= n-f) {
      shouldRecover.resolve()
      result.resolve(recoveredValue)
      
      return true
    }
  })
  
  const recoveryData = [...Array(broker.n)]
  broker.receive(epoch, tag+'u', (i, data) => {
    if (recovered) return true
    const [ subShareRaw, subMaskShareRaw, skCommitRaw, shareCommitsRaw, subCoeffCommitsRaw ] = data.split('|')
    const shareCommitRaws = shareCommitsRaw.split(' '),
          subCoeffCommitRaws = subCoeffCommitsRaw.split(' ')
    if (subCoeffCommitRaws.length !== f || shareCommitRaws.length !== n) return;
    
    const subShare = scalar(subShareRaw),
          subMaskShare = scalar(subMaskShareRaw),
          skCommit = point(skCommitRaw),
          shareCommits = shareCommitRaws.map(c => point(c)),
          subCoeffCommits = subCoeffCommitRaws.map(c => point(c))
    
    if (subShare && subMaskShare && skCommit && shareCommits.every(p => p) && subCoeffCommits.every(p => p)) {
      const c_ = hashToStr(skCommitRaw + '|' + shareCommitsRaw + '|' + subCoeffCommitsRaw)
      recoveryData[i] = { subShare, subMaskShare, c_, tested:false }
      
      shouldRecover.then(() => {
        if (recovered) return;
        if (!pedersenCommit(subShare, subMaskShare).equals(polyEval(shareCommits[broker.thisHostIndex], subCoeffCommits, i))) return;
        recoveryData[i].tested = true
        
        let matching = recoveryData.filter(dat => (dat.tested && dat.c_ === c_))
        if (matching.length >= f+1) {
          recoveredValue.resolve({ share, maskShare, skCommit, shareCommits })
          recovered = true
        }
      }
    }
  })
  
  return result
}

// ---------------------------------------------------------------

// Based on Cachin-Kursawe-Shoup threshold signature-based common coin
// using Boldyreva threshold signatures, but rather than verifying the
// shares using a pairing we instead use a Chaum-Pedersen NIZK to prove
// equality of discrete logs. Note this precludes aggregate verification.
function commonCoin(epoch, tag, sk, pks, broker, t) {
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
function setupHeavyCommonCoin(epoch, tag, broker, reliableBroadcast, reliableReceive) {
  const f = (broker.n - 1)/3|0
  const id = epoch.length+' '+epoch+tag
  const result = defer()

  // Each node deals a secret
  const r = genSk()
  AVSSPHDeal(epoch, tag+'a'+broker.thisHostIndex, r, broker, reliableBroadcast)
  
  const avss_instances = [...Array(broker.n)].map((_, i) => 
    AVSSPHReceive(epoch, tag+'a'+i, i, broker, reliableReceive))
  
  const receivedShares = [...Array(broker.n)]
  const C = [ ], G = [ ]
  let accepted = false
  avss_instances.map((p, i) => p.then(shareAndCommits => {
    C.push(i)
    receivedShares[i] = shareAndCommits
    if (!accepted && C.length >= f+1) {
      reliableBroadcast(epoch, tag+'c', JSON.stringify(C), broker)
      accepted = true
    }
  }))
}

function keyGenSync(epoch, tag, t, broker) {
  
}
