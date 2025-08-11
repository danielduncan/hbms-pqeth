use sha256;

global CONST_N: u32 = 4; // number of sigs to aggregate
global W: u32 = 128 / 8; // WOTS param in bytes
global K: u32 = 4; // tree depth
global CONST_LEN: u32 = 32; // CONST_LENgth of hash output in bytes
global L: u32 = CONST_LEN / W; // number of signatures
global MAX_N: u32 = W;

global TWEAKMESSAGE: u8 = 0x00;
global TWEAKTREE: u8 = 0x01;
global TWEAKCHAIN: u8 = 0x02;

type Sig = (u32, [[u8; CONST_LEN]; L], [[u8; CONST_LEN]; K]);

// good old SHA-256 - x is a 32 byte array, n is number of times it is hashed
fn H(mut x: [u8; CONST_LEN], n: u32, tweak: u8) -> [u8; CONST_LEN] {
    for i in 0..MAX_N * 8 {
        if i < n {
            let tweaked = x.concat([tweak]);
            x = sha256::digest(tweaked);
        }
    }
    x
}

// sig is a SHA-256 hash WOTS+ sig
// message has been replaced with its hash
fn verify_wots(sig: [[u8; CONST_LEN]; L], hash: [u8; CONST_LEN]) -> [u8; CONST_LEN] {
    let mut pks: [[u8; CONST_LEN]; L] = [[0; CONST_LEN]; L];

    for i in 0..L {
        let mut chunk: [u8; W] = [0; W];
        for j in 0..W {
            chunk[j] = hash[(i * W + j)];
        }

        // convert chunk to 32 bit int
        let mut x: u32 = 0;
        for j in 0..W {
            x = x << 8 | chunk[j] as u32;
        }

        let j = (W * 8) - (x % (W * 8));

        pks[i] = H(sig[i], j, TWEAKCHAIN);
    }

    // combine all pks
    let mut pk: [u8; L * CONST_LEN] = [0; L * CONST_LEN];
    for i in 0..L {
        for j in 0..CONST_LEN {
            pk[i * CONST_LEN + j] = pks[i][j] as u8;
        }
    }

    sha256::digest(pk.concat([TWEAKCHAIN]))
}

fn merkle_root(pk: [u8; CONST_LEN], path: [[u8; CONST_LEN]; K], index: u32) -> [u8; CONST_LEN] {
    let mut node = pk;
    let mut idx = index;

    for level in 0..K {
        let sibling = path[level];
        if idx % 2 == 0 {
            node = sha256::digest((node.concat(sibling)).concat([TWEAKTREE]));
        } else {
            node = sha256::digest((sibling.concat(node)).concat([TWEAKTREE]));
        }
        idx /= 2;
    }
    node
}

fn xmss_verify(
    index: u32,
    wots: [[u8; CONST_LEN]; L],
    path: [[u8; CONST_LEN]; K],
    hash: [u8; CONST_LEN],
    pk: [u8; CONST_LEN],
) -> bool {
    let leaf: [u8; CONST_LEN] = verify_wots(wots, hash);
    let root: [u8; CONST_LEN] = merkle_root(leaf, path, index);
    root == pk
}

fn main(N: u32,
    LEN: u32,
    W: u32,
    L: u32,
    K: u32,
    message: pub [u8; CONST_LEN],
    sigs: pub [Sig; CONST_N],
    pks: pub [[u8; CONST_LEN]; CONST_N]) {
    let hash: [u8; 32] = sha256::digest(message.concat([TWEAKMESSAGE]));
    for i in 0..CONST_N {
        let index = sigs[i].0;
        let wots = sigs[i].1;
        let path = sigs[i].2;
        let valid = xmss_verify(index, wots, path, hash, pks[i]);
        assert(valid);
    }
}

#[test]
fn test_main() {}
