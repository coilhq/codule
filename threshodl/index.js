const EC = require('elliptic').ec
const sha = require('sha.js')
const { randomBytes } = require('crypto')
const BN = require('bn.js')
const HmacDRBG = require('hmac-drbg')

const ecc = new EC('secp256k1')
const Fr = BN.red(ecc.curve.redN)

const skLength = 32
const pkLength = 33

// ------------------- Crypto object wrappers -------------------------

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
      precompute:() => val.precompute(),
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

// ------------------- Crypto object manipulation functions -------------------------

// generate a new uniformly random scalar
function genSk() {
  while (true) {
    const r = new BN(randomBytes(skLength))
    
    // check if byte sequence lies outside the scalar field
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

// hash m to a uniformly distributed scalar
function hashToScalar(m) {
  while (true) {
    const r = new BN(hashToBuf(i+'||'+m))
    
    // check if byte sequence lies outside the scalar field
    if (r.cmpn(0) <= 0 || r.cmp(ecc.curve.n) >= 0)
      continue;
    
    return scalar(r)
  }
}

// hash m to a uniformly distributed elliptic curve point
function hashToPoint(m) {
  let buf = Buffer.alloc(pkLength), ret
  
  // uniformly choose whether the y-coord is odd or even
  buf[0] = (hashToBuf(m)[0] % 2) ? 2 : 3

  for (let i = 0; ; i++) {
    // uniformly choose the x-coord; has a ~50% chance of lying on the curve
    buf.set(hashToBuf(i+'||'+m), 1)

    try {
      // TODO this code currently involves a square root even if buf is not on the curve
      // due to the way elliptic.js works. this could be made ~2x faster using fast
      // Legendre symbol computation
      ret = ecc.curve.decodePoint(buf)
      break
    } catch (e) { }
  }

  return point(ret)
}

function add(P1, P2, ...Pn) {
  return !P2 ? P1 : add(P1.add(P2), ...Pn)
}

function mul(P1, P2, ...Pn) {
  return !P2 ? P1 : mul(P1.mul(P2), ...Pn)
}

// ------------------- Serialization utility functions -------------------------

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

// ------------------- Other utility functions -------------------------

// turns a function:index -> object into an array of objects
function arrayOf(n, cb = () => undefined) {
  return [...Array(n)].map((_, i) => cb(i))
}

// creates a promise that can be resolved independent of construction
function defer() {
  let resolve, reject
  const promise = new Promise((res, rej) => { resolve = res; reject = rej })
  return { resolve, reject, promise, then:cb => promise.then(cb) }
}

// ------------------- Constants -------------------------

const G = point(ecc.g)
const G1 = hashToPoint('1')
const AVSSG = hashToPoint('2')
G.precompute() // should already be precomputed, just a sanity check
G1.precompute()
AVSSG.precompute()

// ------------------- Merkle tree manipulation functions -------------------------

// array of bits (0=left, 1=right) indicating how to descend from root to a given leaf index
function pathToLeaf_(leaf, treeDepth) {
  return arrayOf(treeDepth, i => (leaf >> (treeDepth-1-i)) % 2)
}

// depth of a tree with num leaves
function depth_(num) {
  let d = 0
  while ((num-1 >> d) > 0) d++
  
  return d
}

// num leaves in a full tree of the same height
function roundUpPow2_(num) {
  return (1 << depth_(num))
}

// paddedData should always be a power of 2
function merkleConstruct_(paddedData) {
  if (data.length > 1) {
    const lnode = merkleConstruct_(paddedData.slice(0, paddedData.length/2)),
          rnode = merkleConstruct_(paddedData.slice(paddedData.length/2, paddedData.length))
    
    return [ 'node||'+hashToStr(lnode[0]+'| |'+rnode[0]), lnode, rnode ]
  } else if (data[0] === 'empty leaf') {
    return [ 'empty leaf||'+hashToStr('empty leaf') ]
  } else return [ 'leaf||'+hashToStr(JSON.stringify(data[0])) ]
}

// returns a list (ordered bottom -> root) of hashes of neighboring nodes on the branch from the given leaf
// TODO memoization might be good
function merkleBranch_(tree, depth, leaf) {
  const side = pathToLeaf_(leaf, depth)[0]
  if (depth > 0)
    return [ ...merkleBranch_(tree[1+side], depth-1, leaf - (side << (depth-1))), tree[2-side][0] ]
  else
    return [ ]
}

// builds the actual Merkle tree over our data, returns a function to pull branches from it
function merkleConstruct(data) {
  // for simplicity we use padded Merkle trees to avoid complications from unbalanced trees
  const paddedData = data.concat(arrayOf(roundUpPow2_(data.length)-data.length, () => 'empty leaf'))
  
  const tree = merkleConstruct_(paddedData)
  return { root:tree[0].slice(6), branch:(leaf) => merkleBranch_(tree, depth_(data.length), leaf) }
}

// verify that datum was in the tree under root, and wasn't a padding leaf
function merkleBranchVerify(leaf, datum, branch, root) {
  const pathFromLeaf = pathToLeaf_(leaf, branch.length).reverse()
  return branch.reduce((acc, sideHash, i) => {
    return 'node||'+hashToStr(pathFromLeaf[i] ? (sideHash+'| |'+acc) : (acc+'| |'+sideHash))
  }, 'leaf||'+hashToStr(JSON.stringify(datum))) === 'node||'+root
}

// ------------------- Zero-knowedge proofs -------------------------

// --- Schnorr proofs --- //
// Schnorr proofs allow you to prove in zero knowledge that you know some
// scalar sk such that pk = sk*G.

// format: [ challenge, response ]
const schnorrDecode = ['S', 'S']

function schnorrSign(sk, m) {
  // using deterministic nonces for safety
  const nonce = hashToScalar(m.length + '||schnorr||' + hashToString(sk.encodeStr()) + '||' + m)
  const pubNonce = nonce.mul(G)
  
  // TODO might as well hash the public key in here as well
  const c = hashToScalar(pubNonce.encodeStr() + '||' + m)

  return [ c, nonce.sub(sk.mul(c)) ]
}

function schnorrVerify(pk, m, [ c, z ]) {
  const pubNonce_ = z.mul(G).add(pk.mul(c))
  const c_ = hashToScalar(pubNonce_.encodeStr() + '||' + m)
  
  return c.equals(c_)
}

// --- Chaum-Pedersen proofs --- //
// Chaum-Pedersen proofs allow you to prove in zero knowledge that
// a given set of elliptic curve points are Diffie-Hellman triples.
// i.e., given points (pk, H, sig) I prove that I know some scalar sk such
// that pk = sk*G and sig = sk*H.
//
// NOTE this protocol is UNSAFE to use with curves that have a cofactor!

// format: [ sig, proof=[ challenge, response ] ]
const chaumPedersenDecode = ['P', ['S', 'S']]

function chaumPedersenProve(sk, m) {
  // if m is already a point, then we're proving knowledge of sk s.t. pk = sk*G, sig = sk*m
  // if m is a message, then we instead prove pk = sk*G, sig = sk*hashToPoint(m), which is
  // sort of like a signature over m.
  const H = (m.isPoint) ? m : hashToPoint(m)
  
  // using deterministic nonces for safety
  const nonce = hashToScalar(m.length + '||CP||' + hashToString(sk.encodeStr()) + '||' + m)
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

// produce a perfect-hiding commitment to val.
// the commitment is c = val*G + mask*G1. if mask is random, this reveals
// nothing (information theoretically) about val. however producing
// (val',mask') such that c = val'*G + mask'*G1 is hard without knowledge
// of the discrete log of G1.
function pedersenCommit(val, mask) {
  if (!mask) mask = genSk()
  return val.mul(G).add(mask.mul(G1))
}

function pedersenVerify(val, mask, commitment) {
  return pedersenCommit(val, mask).equals(commitment)
}

// --- Perfect hiding Chaum-Pedersen proofs --- //
// these proofs are similar to standard CP proofs, except instead of using
// pk = sk*G, we instead use a Pedersen commitment to sk.
//
// NOTE this protocol is UNSAFE to use with curves that have a cofactor!

// format: [ sig, proof=[ challenge, response1, response2 ] ]
const chaumPedersenPHDecode = ['P', ['S', 'S', 'S']]

function chaumPedersenPHProve(sk, mask, m) {
  const H = hashToPoint(m)
  
  // using deterministic nonces for safety
  const nonce = hashToScalar(m.length + '||CPPH0||' + hashToString(sk.encodeStr()) + '||' + m)
  const nonce1 = hashToScalar(m.length + '||CPPH1||' + hashToString(sk.encodeStr()) + '||' + m)
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

// --- Perfect hiding Chaum-Pedersen proofs --- //
// these proofs are similar to standard CP proofs, except instead of using
// pk = sk*G, we instead use pk = sk*G + mask*G1. this reveals no information
// about sk (information theoretically), but it's computationally difficult to
// find sk',mask' such that pk = sk'*G + mask'*G1.
//
// NOTE this protocol is UNSAFE to use with curves that have a cofactor!

// format: [ sig, proof=[ challenge, response1, response2 ] ]
const pedersenPKDecode = ['P', ['S', schnorrDecode]]

function pedersenPKProve(val, mask) {
  const pk = val.mul(G)
  return [ pk,  [ mask, schnorrSign(val, '') ] ]
}

function pedersenPKVerify([ pk, [ mask, sig ] ], commitment) {
  return (pk.add(mask.mul(G1)).equals(commitment) && schnorrVerify(pk, '', sig))
}

// ---------------------------------------------------------------

// evaluates the polynomial input p at evalPoint
function polyEval(evalPoint, constTerm, ...coeffs) {
  return add(constTerm, ...coeffs.map((c, j) => c.mul(scalar(evalPoint).toThe(scalar(j+1)))))
}

// returns a function mapping a node index to p(i+1)
function polyEvalPlayer(constTerm, ...coeffs) {
  return i => polyEval(i+1, constTerm, ...coeffs)
}

// NOTE polynomial coeffs are derived deterministically from sk, so knowing sk immediately
// allows you to compute everyone's secret shares.
function secretShare(sk, t, n) {
  const coeffs = [ sk, ...arrayOf(t-1, (i) => hashToScalar(hashToString(sk.encodeStr()) + '||poly||' + i)) ]
  const shares = arrayOf(n, polyEvalPlayer(...coeffs))
  return { shares, coeffs }
}

// evaluate at x_ the lowest-degree polynomial interpolating shares_
// shares is formatted as an array of array pairs [i, share] indicating
// all the points to be interpolated.
function interpolateListAt(x_, shares) {
  const x = scalar(x_)
  
  // the values being interpolated can either be scalars or elliptic curve points
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

// evaluate at x_ the lowest-degree polynomial interpolating shares_
// shares is formatted as an array where shares[i] is expected to be truth-y iff
// (i, shares[i]) is an x-y pair to be interpolated.
function interpolateAt(x_, shares) {
  return interpolateListAt(x_, shares.reduce((acc, s, i) => { if (s) acc.push([i+1, s]); return acc }, [ ]))
}

function interpolateList(shares) {
  return interpolateListAt(0, shares)
}

function interpolate(shares) {
  return interpolateAt(0, shares)
}

// ---------------------------------------------------------------

// play the role of dealer for sharing threshold shards of sk, with reconstruction threshold t.
// for certain use cases one might want to keep sk*G secret, so this function only reveals the
// value sk*AVSSG, where AVSSG is a random point not used for anything else.
//
// TODO add polynomial commitments for better communication complexity
// TODO investigate optimizations from https://arxiv.org/abs/1902.06095
function AVSSDeal(tag, sk, broker, t) {
  const n = broker.n, f = (n - 1)/3|0
  t = t||f+1
  
  // coeffs is a polynomial p of degree t-1, and shares[i] = p(i+1)
  const { shares:shares, coeffs:coeffs } = secretShare(sk, t, n)
  
  // for each secret share s_i, produces a polynomial p_i of degree f, then slices
  // the shares of these polynomials so that subShares[i][j] = p_i(j+1), subCoeffs[i] = p_i.
  const { subShares, subCoeffs } = shares.map((s, i) => secretShare(s, f+1, n))
                                         .reduce(({ subShares, subCoeffs }, { shares, coeffs }) => {
                                           return { subShares+[shares], subCoeffs+[coeffs] }
                                         }, { subShares:[ ], subCoeffs:[ ] })
  
  // subShareSlices[i][j] = p_j(i+1), so that seeing subShareSlices[_][j] for enough values
  // allows you to interpolate p_j.
  const subShareSlices = arrayOf(n, i => arrayOf(n, j => subShares[j][i])) // (n, n)
  
  const pubCoeffs = coeffs.map(coeff => coeff.mul(AVSSG)) // (t)
  const pubSubCoeffs = subCoeffs.map(arr => arr.map(coeff => coeff.mul(AVSSG))) // (n, f+1)
  const pubSubShares = subShares.map(arr => arr.map(share => share.mul(AVSSG))) // (n, n)

  // reliably broadcast all the public verification keys and to each node send its slices of the subshares.
  //
  // we don't need to send the actual share because it will be reconstructed from subshares pulled from
  // other nodes' slices. similarly, pk and pubCoeffs are derived from pubSubCoeffs.
  const mFunc = i => encodeData([ subShareSlices[i], pubCoeffs, pubSubCoeffs, pubSubShares ])
  broker.send(tag+'i', mFunc)
}

function AVSSReceive(tag, sender, broker, t) {
  const n = broker.n, f = (n - 1)/3|0
  t = t||f+1
  
  const result = defer(), onRecoveredData = defer()
  
  let echoed = false, readied = false, finished = false
  let share, pk, pubCoeffs, pubSubCoeffs, h, tree
  
  // initial message received directly from the dealer
  broker.receiveFrom(tag+'i', sender, m => {
    if (!echoed) {
      echoed = true
      
      decodeData(m, [ arrayOf(n, _ => 'S'), arrayOf(t, _ => 'P'),
                      arrayOf(n, _ => arrayOf(f+1, _ => 'P')),
                      arrayOf(n, _ => arrayOf(n, _ => 'P'))], 
        ([ subShareSlice, pubCoeffs, pubSubCoeffs, pubSubShares ]) => {
        
        // checking pubSubShares and pubSubCoeffs are coherent.
        {
          // check that the polynomial interpolating pubSubShares[i] has degree at most f for all i.
          //
          // this works because two distinct small-degree polynomials are only equal on a negligible number
          // of points, and interpolated polynomials always have degree < n.
          // thus if the first interpolated value equals the second, then with overwhelming probability
          // the polynomial interpolating pubSubShares[i] is pubSubCoeffs[i], which has degree f.
          let randPoint = genSk()
          for (let i = 0; i < n; i++) {
            let interpolatedPolyAtRandPoint = interpolateAt(randPoint, pubSubShares[i])
            let pubSubCoeffsAtRandPoint = polyEval(randPoint, ...pubSubCoeffs[i])
            if (interpolatedPolyAtRandPoint !== pubSubCoeffsAtRandPoint)
              return;
          }
        }
        
        // by the check above we know pubSubCoeffs[i][0] = p_i(0), where p_i is the degree f polynomial
        // interpolating pubSubShares[i].
        let pubShares = pubSubCoeffs.map(arr => arr[0])
        
        // checking pubShares and pubCoeffs are coherent.
        {
          // check that the polynomial interpolating pubShares has degree at most t-1, same way as before.
          let interpolatedPolyAtRandPoint = interpolateAt(randPoint, pubShares)
          let pubCoeffsAtRandPoint = polyEval(randPoint, ...pubCoeffs)
          if (interpolatedPolyAtRandPoint !== pubCoeffsAtRandPoint)
            return;
        }
        
        // check all our subshares are valid evaluations of the polys committed to under pubSubCoeffs
        if (!subShareSlice.every((subShare, i) => subShare.mul(AVSSG).equals(pubSubShares[i][broker.thisHostIndex])))
          return;
        
        let pk = pubCoeffs[0]
        
        // build a Merkle tree over all the verification keys for all subshares.
        tree = merkleConstruct(pubSubShares.reduce((acc, arr) => acc+arr.map(p => p.encodeStr()), []))
        
        // send every node our subShare of their share, along with a merkle proof for it.
        // TODO erasure-code pubShares to reduce communication complexity to n^2.
        const mFunc = i => encodeData([ subShareSlice[i], pk, pubShares, tree.root, tree.branch(i*n+broker.thisHostIndex) ])
        broker.send(tag+'e', mFunc)
      })
    }
  })
  
  // we now do a sort of reliable broadcast to ensure that everyone received consistent
  // public verification data.
  broker.receive(tag+'e', (i, m) => {
    if (finished) return;

    decodeData(m, [ 'S', 'P', arrayOf(n, _ => 'P'), 'T', arrayOf(depth_(n*n), _ => 'T')], 
      ([ subShare, pk, pubShares, root, branch ]) => {
      pubSubShare = subShare.mul(AVSSG)
      if (!merkleBranchVerify(broker.thisHostIndex*n + i, pubSubShare.encodeStr(), branch, root)) return;
      
      // pk and pubShares are already determined by the data committed to under root, but we hash them in anyway
      // just for caution in case there was a bug/error.
      hash = hashToStr(pk.encodeStr() + '||' + pubShares.reduce((acc,p) => acc+'||'+p.encodeStr(),'')+'||'+root)
      
      // add node i and its data to the list of nodes that echoed hash
      hashes.set(hash, hashes.get(hash)||[] + [[ i, subShare ]])
      hashesPubData.set(hash, [pk, pubShares])
      
      hashes.forEach((hash, support) => {
        // ready after seeing n-f echoes for a common public data hash
        if (support.length >= n-f && !readied) {
          h = hash
          broker.broadcast(tag+'r', hash)
          readied = true
        }
        
        // once we learn that this hash is the unique value that was committed to, we can reconstruct
        // our share from f+1 subshares corresponding to messages sent under that hash.
        if (support.length >= f+1 && h && h === hash) {
          onRecoveredData.resolve({
            share: interpolateList(support)
            pk: hashesPubData.get(hash)[0]
            pubShares: hashesPubData.get(hash)[1]
          })
        }
      })
    })
  })
  
  broker.receive(tag+'r', (i, hash) => {
    readyHashes.set(hash, readyHashes.get(hash)||0 + 1)
    
    readyHashes.forEach((hash, supportCount) => {
      // ready if we haven't done so already after seeing f+1 other readies
      if (supportCount >= f+1 && !readied) {
        h = hash
        broker.broadcast(tag+'r', hash)
        readied = true
      }
      
      if (supportCount >= n-f) {
        // due to asynchrony and Byzantine behavior the "if (support.length >= f+1 && h && h === hash)"
        // check above might only be triggered before h is set, so we need to check if we can recover
        // here as well.
        if (hashes.has(hash) && hashes.get(hash).length >= f+1) {
          onRecoveredData.resolve({
            share: interpolateList(hashes.get(hash))
            pk: hashesPubData.get(hash)[0]
            pubShares: hashesPubData.get(hash)[1]
          })
        }
        
        // n-f readies guarantees every node will eventually recover their share
        onRecoveredData.then(r => result.resolve(r))
      }
    })
  })
  
  return result.promise
}

// ---------------------------------------------------------------

// Based on the Cachin-Kursawe-Shoup threshold signature common coin
// using Boldyreva threshold signatures, but rather than verifying the
// shares using a pairing we instead use a Chaum-Pedersen NIZK to prove
// equality of discrete logs. Note this precludes aggregate verification.
function setupCommonCoin(tag, broker, share, pubShares) {
  // after initialization, this resolves to a function that can be called
  // with a subtag tag_ to instantiate arbitrarily many coins.
  return Promise.resolve((tag_) => {
    const n = broker.n, f = (n - 1)/3|0
    const result = defer()

    const id = tag.length+' '+tag+tag_
    
    // our coin share is share*hashToPoint(id), and we include a CP proof that this
    // coin share was produced correctly.
    broker.broadcast(tag+tag_, encodeData(chaumPefersenProve(share, id)))
    
    const coinShares = arrayOf(n)
    let count = 0
    broker.receive(tag+tag_, (i, m) => {
      decodeData(m, chaumPedersenDecode, ([ sig, proof ]) => {
        if (chaumPedersenVerify(pubShares[i], id, [ sig, proof ])) {
          coinShares[i] = sig
          count++
          if (count >= f+1) {
            // the coin value is the string hash of p(0), where p is the polynomial interpolating
            // [ i+1, share[i]*hashToPoint(id) ] for each node i.
            result.resolve(hashToStr(interpolate(coinShares)))
          }
        }
      })
    })
    
    return result.promise
  })
}

// a subprimitive of asynchronous distributed key gen. the purpose of this protocol is to assign
// to each honest node a threshold-shared secret that no one knows.
//
// works by having each node i deal a shared secret s_i through AVSS. i then chooses a list A_i
// consisting of f+1 terminated AVSS instaces and reliably broadcasts A_i. i's shared secret is then
// defined to be the sum of the shared secrets from all instances in A_i, which is guaranteed to be
// secret since at least one of those instances must have been from an honest node.
//
// returns:
//   - G: a reference to an array of node indices for all nodes whose shared secret has been built.
//   - As: an array of promises for each node's A list, describing how to reconstruct its shared secret.
//   - shares: an array of promises for the secret share and public verification data we get from each
//             AVSS instance.
//   - onAddToG: a callback that can be called whenever a new node is added to G.
//
// NOTE some nodes may be assigned the same shared secret.
function setupKeygenProposals(tag, broker, reliableBroadcast, reliableReceive) {
  const n = broker.n, f = (n - 1)/3|0
  const result = defer()

  // each node deals a secret
  const r = genSk()
  AVSSDeal(tag+'a'+broker.thisHostIndex, r, broker)
  
  // participate as a receiver in every node's AVSS instance
  const AVSSInstances = arrayOf(n, i => 
    AVSSReceive(tag+'a'+i, i, broker))
  
  // C is the list of all nodes whose AVSS instance has successfully terminated.
  // each node will get a shared secret corresponding to them; the secret corresponding
  // to us will be the sum of the secrets shared by nodes in C. importantly, NO ONE,
  // not even ourself, knows the shared secret corresponding to us.
  const C = [ ]
  
  let accepted = false, readied = false
  
  // arr is a list of pairs [ p1, p2 ], where p1 and p2 are promises for a list of node indices.
  // calling update(arr) will wait until p1 resolves, then check if C contains p1 and if so
  // resolves p2 to p1.
  //
  // by calling update(arr) every time C is updated, this ensures that p2 will eventually resolve to
  // p1 iff p1 eventually is contained in C.
  function update(arr) {
    arr.forEach(async ([p1, p2]) => {
      const A = await p1
      if (A.every(i => C.includes(i)))
        p2.resolve(A)
    })
  }
  
  const pendingAttaches = arrayOf(n, () => [ defer(), defer() ]),
        pendingAttachesFinalized = arrayOf(n, () => [ defer(), defer() ])
  
  AVSSInstances.forEach(async (p, i) => {
    await p
    
    // i's AVSS instance terminated succesfully, so add it to C and update the lists dependent on C.
    C.push(i)
    update(pendingAttaches)
    update(pendingAttachesFinalized)
    
    // once C is big enough, reliably broadcast it to everyone else.
    // this is reliably broadcasted because we need every node to agree on the shared secret
    // corresponding to us.
    if (!accepted && C.length >= f+1) {
      reliableBroadcast(tag+'c'+broker.thisHostIndex, JSON.stringify(C), broker)
      accepted = true
    }
  })
  
  
  
  // G is the list of all nodes from whom we've successfully received their reliably broadcasted C-list
  const G = [ ]
  
  // attaches[i] resolves to a stringified list of i's C-list after we've received and verified it
  const attaches = arrayOf(n, i =>
    reliableReceive(tag+'c'+i, i, broker, m => {
      try {
        // on receiving a node's C-list, try to parse it as an array then remove duplicates
        // and check if it's large enough.
        let A = [...(new Set(JSON.parse(m))).values()]
        if (A.length >= f+1) {
          // pendingAttaches[i][1] will resolve to A only after we've verified that the AVSS
          // instace for every node in A's C-list actually DOES terminate.
          pendingAttaches[i][0].resolve(A)
        }
      } catch (e) { }
      
      // only echo the list after we've verified it.
      return pendingAttaches[i][1].then(A => JSON.stringify(A))
    })
  )
  
  // in case G gets further updated after we've moved on to future steps, this function can be
  // modified to allow calling back whenever G is updated.
  let onAddToG_ = () => { }
  
  attaches.forEach(async (p, i) => {
    const A = JSON.parse(await p)
    pendingAttachesFinalized[i][0].resolve(A)
    
    // wait until we've accepted reliable broadcast for i's C-list AND we've verified its validity.
    await pendingAttachesFinalized[i][1]
    
    G.push(i)
    onAddToG_()
    
    // we've received as many C-lists as we can reasonably wait for, so we move on to trying
    // to stabilize G.
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

// after we've worked out assigning shared secrets to as many nodes as possible, we now need to
// "stabilize" G. i.e., we want to pass G-sets back and forth until we can guarantee that the
// intersection of ALL honest nodes' G-sets contains a constant fraction of all the nodes in the
// more specifically, the protocol we use guarantees the intersection has size at least n/2 nodes.
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
  
  const share = add(...shares_.map(s => s.share))
  const maskShare = add(...shares_.map(s => s.maskShare))
  const skCommit = add(...shares_.map(s => s.skCommit))
  const shareCommits = arrayOf(n, x => add(...shares_.map(s => s.shareCommits[x])))
  
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
        await Promise.all([ keyGen(tag+'n'+iter+'_', broker),
                            keyGen(tag+'b'+iter+'_', broker) ])
      
      const kbShare = k.mul(b), proof = chaumPedersenProve(k, bSharePKs[broker.thisHostIndex])
      broker.broadcast(tag+'r'+iter, encodeData([ kbShare, proof ]))
      
      const kbShares = arrayOf(n)
      let count = 0, finished = false
      broker.receive(tag+'r'+iter, (i, m) => {
        if (finished) return;
        decodeData(m, ['S', chaumPedersenDecode], ([ kbShare, proof ]) => {
          if (chaumPedersenVerify(kSharePKs[i], bSharePKs[i], proof) &&
              proof[0].equals(kbShare.mul(G))) {
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
        decodeData(m, ['S', chaumPedersenDecode], ([ sShare, proof ]) => {
          if (chaumPedersenVerify(pks[i], kInvSharePKs[i], proof) &&
              proof[0].mul(r).add(kInvSharePKs[i].mul(msgHash))
                .equals(sShare.mul(G))) {
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
    
    if (s.cmpn(0) === 0)
      continue;

    let recoveryParam = (kPK.val.getY().isOdd() ? 1 : 0) |
                        (kpX.cmp(r) !== 0 ? 2 : 0)

    // Use complement of `s`, if it is > `n / 2`
    if (s.cmp(ecc.nh) > 0) {
      s = ecc.curve.n.sub(s)
      recoveryParam ^= 1
    }

    return toDER(r.val.fromRed(), s)
  }
}

module.exports = {
  setupHeavyCommonCoin,
  setupCommonCoin,
  keyGenAsync,
  thresholdECDSA
}
