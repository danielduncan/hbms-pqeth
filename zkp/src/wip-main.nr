use sha256;

global MAX_BITS: u32 = 256; // max length of hash output in bits
global MAX_BYTES: u32 = MAX_BITS / 8; // max length of hash output in bytes
global MAX_N: u32 = 100; // max number of signatures to aggregate
global MAX_W: u32 = MAX_BITS; // max WOTS chunk width in bits (MAX_W = MAX_BITSGTH -> single sig)
global MAX_L: u32 = MAX_BITS; // max number of WOTS signatures in a single XMSS signature (single bit sig)
global MAX_K: u32 = 40; // max Merkle tree depth - 40 corresponds to a lifetime of 2^40

global TWEAKMESSAGE: u8 = 0x00;
global TWEAKTREE: u8 = 0x01;
global TWEAKCHAIN: u8 = 0x02;

type Sig = (u32, [[u8; MAX_BYTES]; MAX_L], [[u8; MAX_BYTES]; MAX_K]);

fn get_bits(x: [u8; MAX_BYTES]) -> [u1; MAX_BITS] {
    let mut bits: [u1; MAX_BITS] = [0; MAX_BITS];
    for i in 0..32 {
        for j in 0..8 {
            bits[i * 8 + j as u32] = ((x[i] as u8 >> (7 - j)) & 1) as u1;
        }
    }
    bits
}

fn get_bytes(bits: [u1; MAX_BITS]) -> [u8; MAX_BYTES] {
    let mut bytes: [u8; MAX_BYTES] = [0; MAX_BYTES];
    for i in 0..(MAX_BYTES) {
        for j in 0..8 {
            bytes[i] |= (bits[i * 8 + j as u32] as u8) << (7 - j);
        }
    }
    bytes
}

// Only compatible with SHA-256 for proof of concept
fn H(mut x: [u8; MAX_BYTES], n: u32, tweak: u8) -> [u1; MAX_BITS] {
    for _ in 0..n {
        let tweaked: [u8; 33] = x.concat([tweak]);
        x = sha256::digest(tweaked);
    }

    // convert to bit array
    let bits = get_bits(x);
    bits
}

// signature is a WOTS+ sig (SHA-256 hash)
// message has been replaced with its hash
fn verify_wots(
    W: u32,
    L: u32,
    sig: [[u8; MAX_BYTES]; MAX_L],
    hash: [u1; MAX_BITS],
) -> [u1; MAX_BITS] {
    let mut pks: [[u1; MAX_BITS]; MAX_L] = [[0; MAX_BITS]; MAX_L];

    for i in 0..L {
        let mut chunk: [u1; MAX_W] = [0; MAX_W];
        for j in 0..W {
            chunk[j] = hash[(i * W + j)];
        }

        // convert chunk to int
        let mut x: u32 = 0;
        for j in 0..W {
            x = x << 1 | chunk[j] as u32;
        }

        let j = W - (x % W);

        pks[i] = H(sig[i], j, TWEAKCHAIN);
    }

    // combine all pks
    let mut pk: [u8; MAX_L * MAX_BITS] = [0; MAX_L * MAX_BITS];
    for i in 0..L {
        for j in 0..MAX_BITS {
            pk[i * MAX_BITS + j] = pks[i][j] as u8;
        }
    }

    get_bits(sha256::digest(pk.concat([TWEAKCHAIN])))
}

fn merkle_root(
    K: u32,
    pk: [u1; MAX_BITS],
    path: [[u8; MAX_BYTES]; MAX_K],
    index: u32,
) -> [u1; MAX_BITS] {
    let mut node = pk;
    let mut idx = index;

    for level in 0..K {
        let sibling = path[level];
        let mut content: [u8; 2 * MAX_BYTES + 1] = [0; 2 * MAX_BYTES + 1];
        let node_bytes = get_bytes(node);

        if idx % 2 == 0 {
            content = (node_bytes.concat(sibling)).concat([TWEAKTREE])
        } else {
            content = (sibling.concat(node_bytes)).concat([TWEAKTREE]);
        }
        node = get_bits(sha256::digest(content));
        idx /= 2;
    }
    node
}

fn xmss_verify(
    W: u32,
    L: u32,
    K: u32,
    index: u32,
    wots: [[u8; MAX_BYTES]; MAX_L],
    path: [[u8; MAX_BYTES]; MAX_K],
    hash: [u8; MAX_BYTES],
    pk: [u8; MAX_BYTES],
) -> bool {
    let leaf: [u1; MAX_BITS] = verify_wots(W, L, wots, get_bits(hash));
    let root: [u1; MAX_BITS] = merkle_root(K, leaf, path, index);
    root == get_bits(pk)
}

fn main(
    N: u32,
    LEN: u32,
    W: u32,
    L: u32,
    K: u32,
    message: pub [u8; MAX_BYTES],
    sigs: pub [Sig; MAX_N],
    pks: pub [[u8; MAX_BYTES]; MAX_N],
) {
    assert(N <= MAX_N);
    assert(LEN <= MAX_BITS);
    assert(W <= MAX_W);
    assert(K <= MAX_K);
    assert(L <= MAX_L);

    let hash: [u8; MAX_BYTES] = sha256::digest(message.concat([TWEAKMESSAGE]));

    for i in 0..N {
        let index = sigs[i].0;
        let wots = sigs[i].1;
        let path = sigs[i].2;
        let valid = xmss_verify(W, L, K, index, wots, path, hash, pks[i]);
        assert(valid);
    }
}

#[test]
fn test_main() {}
