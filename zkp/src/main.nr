use sha256;

global N: u32 = 4; // number of sigs to aggregate
global W: u32 = 8; // WOTS param
global L: u32 = 256 / 8; // number of signatures
global K: u32 = 5; // tree depth
global STRLEN: u32 = 10;
global HASHLEN: u32 = 32; // length of hash output in bytes
global MAX_N: u32 = 100000;

global TWEAKMESSAGE: u8 = 0x00;
global TWEAKCHAIN: u8 = 0x01;
global TWEAKTREE: u8 = 0x02;

type Sig = (u32, [[u8; HASHLEN]; L], [[u8; HASHLEN]; K]);

// good old SHA-256 - x is a 32 byte array, n is number of times it is hashed
fn H(mut x: [u8; HASHLEN], n: u32, tweak: u8) -> [u8; HASHLEN] {
    for i in 0..MAX_N {
        if i < n {
            let tweaked = x.concat([tweak]);
            x = sha256::digest(tweaked);
        }
    }
    x
}

// sig is a SHA-256 hash WOTS+ sig
// message has been replaced with its hash
fn verify_wots(sig: [[u8; HASHLEN]; L], hash: [u8; HASHLEN]) -> [u8; HASHLEN] {
    let mut pks: [[u8; HASHLEN]; L] = [[0; HASHLEN]; L];

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

        let j = W - x % W;

        pks[i] = H(sig[i], j, TWEAKCHAIN);
    }
    let mut pk: [u8; 32] = [0; 32];
    for i in 0..L {
        for j in 0..32 {
            pk[i * 32 + j] = pk[i * 32 + j] << 8 | pks[i][j] as u8;
        }
    }
    H(pk, 1, TWEAKCHAIN)
}

fn merkle_root(pk: [u8; HASHLEN], path: [[u8; HASHLEN]; K], index: u32) -> [u8; HASHLEN] {
    let mut node = pk;
    let mut idx = index;

    for level in 0..K {
        let sibling = path[level];
        if idx % 2 == 0 {
            // need to include tweak
            node = sha256::digest(node.concat(sibling));
        } else {
            node = sha256::digest(sibling.concat(node));
        }
        idx /= 2;
    }
    node
}

fn xmss_verify(
    index: u32,
    wots: [[u8; HASHLEN]; L],
    path: [[u8; HASHLEN]; K],
    hash: [u8; HASHLEN],
    pk: [u8; HASHLEN],
) -> bool {
    let leaf: [u8; HASHLEN] = verify_wots(wots, hash);
    let root: [u8; HASHLEN] = merkle_root(leaf, path, index);

    root == pk
}

fn main(message: pub [u8; STRLEN], sigs: pub [Sig; N], pks: pub [[u8; HASHLEN]; N]) {
    let hash: [u8; 32] = sha256::digest(message);
    for i in 0..N {
        let index = sigs[i].0;
        let wots = sigs[i].1;
        let path = sigs[i].2;
        let valid = xmss_verify(index, wots, path, hash, pks[i]);
        assert(valid);
    }
}

#[test]
fn test_main() {
    main(
        "placeholde".as_bytes(),
        [
            (0, [[0; HASHLEN]; L], [[0; HASHLEN]; K]),
            (1, [[0; HASHLEN]; L], [[0; HASHLEN]; K]),
            (2, [[0; HASHLEN]; L], [[0; HASHLEN]; K]),
            (3, [[0; HASHLEN]; L], [[0; HASHLEN]; K]),
        ],
        [[4; HASHLEN]; N],
    );

    // Uncomment to make test fail
    // main(1, 1);
}
