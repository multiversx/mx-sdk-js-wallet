import * as nobleUtils from "@noble/curves/abstract/utils";
import { bls12_381 as nobleBls } from "@noble/curves/bls12-381";
import { sha512 } from "@noble/hashes/sha512";
import { assert } from "chai";

const Fp = nobleBls.fields.Fp;
const G1 = nobleBls.G1;

describe.only("test BLS compatibility (noble crypto and herumi)", () => {
    it("test BLS implementations", async function () {});

    it("test getWeierstrassLikeHerumi", async function () {
        const inputHex =
            "b14695c802ca943acc28d5e47aec2ce163d3004559fc9d2e1659f5f22ca363f96548e504a6f2b9cab57bcce75c4e9309";
        const expectedOutputHex =
            "fd15a70e718737b6457701e2c134b254d797837f7166300f46360974e3b51ac4d679f7de76d488d52da1c13a3f1bb719";
        const input = nobleUtils.bytesToNumberLE(Buffer.from(inputHex, "hex"));
        const output = getWeierstrassLikeHerumi(input);
        const outputHex = Buffer.from(nobleUtils.numberToBytesLE(output, Fp.BYTES)).toString("hex");

        assert.equal(outputHex, expectedOutputHex);
    });

    it("test setArrayMaskLikeHerumi", async function () {
        const inputHex =
            "f74f2603939a53656948480ce71f1ce466685b6654fd22c61c1f2ce4e2c96d1cd02d162b560c4beaf1ae45f3471dc5cbc1ce040701c0b5c38457988aa00fe97f";
        const expectedOutputHex =
            "f74f2603939a53656948480ce71f1ce466685b6654fd22c61c1f2ce4e2c96d1cd02d162b560c4beaf1ae45f3471dc50b";

        const input = Buffer.from(inputHex, "hex");
        const output = setArrayMaskLikeHerumi(input);
        const outputHex = Buffer.from(output).toString("hex");

        assert.equal(outputHex, expectedOutputHex);
    });

    it("test calcBNComputeWLikeHerumi", async function () {
        const inputHex =
            "f74f2603939a53656948480ce71f1ce466685b6654fd22c61c1f2ce4e2c96d1cd02d162b560c4beaf1ae45f3471dc50b";
        const expectedOutputHex =
            "340d1f61a8fff391e13cf5766327816f7468dbedb2f406e3dbcd629b555baacbc0b4ec07d26fea51f744498540683206";

        const input = nobleUtils.bytesToNumberLE(Buffer.from(inputHex, "hex"));
        const output = calcBNComputeWLikeHerumi(input);
        const outputHex = Buffer.from(nobleUtils.numberToBytesLE(output, Fp.BYTES)).toString("hex");

        assert.equal(outputHex, expectedOutputHex);
    });

    it("test calcBNLoopLikeHerumi", async function () {
        const wHex = "340d1f61a8fff391e13cf5766327816f7468dbedb2f406e3dbcd629b555baacbc0b4ec07d26fea51f744498540683206";
        const tHex = "f74f2603939a53656948480ce71f1ce466685b6654fd22c61c1f2ce4e2c96d1cd02d162b560c4beaf1ae45f3471dc50b";
        const expectedOutputHex =
            "b14695c802ca943acc28d5e47aec2ce163d3004559fc9d2e1659f5f22ca363f96548e504a6f2b9cab57bcce75c4e9389";

        const w = nobleUtils.bytesToNumberLE(Buffer.from(wHex, "hex"));
        const t = nobleUtils.bytesToNumberLE(Buffer.from(tHex, "hex"));

        const output = calcBNLoopLikeHerumi(w, t);
        const outputHex = Buffer.from(projectivePointToBytesLikeHerumi(output)).toString("hex");

        assert.equal(outputHex, expectedOutputHex);
    });

    it("test calcBNLoopLikeHerumiIteration0", async function () {
        const wHex = "340d1f61a8fff391e13cf5766327816f7468dbedb2f406e3dbcd629b555baacbc0b4ec07d26fea51f744498540683206";
        const tHex = "f74f2603939a53656948480ce71f1ce466685b6654fd22c61c1f2ce4e2c96d1cd02d162b560c4beaf1ae45f3471dc50b";
        const expectedOutputHex =
            "b14695c802ca943acc28d5e47aec2ce163d3004559fc9d2e1659f5f22ca363f96548e504a6f2b9cab57bcce75c4e9309";

        const w = nobleUtils.bytesToNumberLE(Buffer.from(wHex, "hex"));
        const t = nobleUtils.bytesToNumberLE(Buffer.from(tHex, "hex"));
        const output = calcBNLoopLikeHerumiIteration0(w, t);
        const outputHex = Buffer.from(nobleUtils.numberToBytesLE(output, Fp.BYTES)).toString("hex");

        assert.equal(outputHex, expectedOutputHex);
    });
});

// Herumi code: https://github.com/herumi/mcl/blob/v2.00/include/mcl/bn.hpp#L2122
function hashAndMapToG1LikeHerumi(message: Uint8Array) {
    const hash = sha512(message);
    const hashMasked = setArrayMaskLikeHerumi(hash);
    return mapToG1LikeHerumi(hashMasked);
}

// Herumi code: https://github.com/herumi/mcl/blob/v2.00/include/mcl/fp.hpp#L371
// x &= (1 << bitLen) - 1
// x &= (1 << (bitLen - 1)) - 1 if x >= p
// void setArrayMask(const S *x, size_t n)
// {
//     const size_t dstByte = sizeof(Unit) * op_.N;
//     if (sizeof(S) * n > dstByte) {
//         n = dstByte / sizeof(S);
//     }
//     bool b = fp::convertArrayAsLE(v_, op_.N, x, n);
//     assert(b);
//     (void)b;
//     bint::maskN(v_, op_.N, op_.bitSize);
//     if (bint::cmpGeN(v_, op_.p, op_.N)) {
//         bint::maskN(v_, op_.N, op_.bitSize - 1);
//     }
//     toMont();
// }
function setArrayMaskLikeHerumi(x: Uint8Array): Uint8Array {
    const mask1 = nobleUtils.bitMask(Fp.BITS);
    const mask2 = nobleUtils.bitMask(Fp.BITS - 1);

    let xAsBigInt = nobleUtils.bytesToNumberLE(x);
    xAsBigInt = xAsBigInt & mask1;

    if (xAsBigInt >= Fp.ORDER) {
        xAsBigInt = xAsBigInt & mask2;
    }

    return nobleUtils.numberToBytesLE(xAsBigInt, Fp.BYTES);
}

function mapToG1LikeHerumi(t: Uint8Array) {
    return calcBNLikeHerumi(t);
}

// Herumi code: https://github.com/herumi/mcl/blob/v2.00/include/mcl/bn.hpp#L362
// "Indifferentiable hashing to Barreto Naehrig curves" by Pierre-Alain Fouque and Mehdi Tibouchi
// https://www.di.ens.fr/~fouque/pub/latincrypt12.pdf
function calcBNLikeHerumi(t: Uint8Array) {
    let tAsBigInt = nobleUtils.bytesToNumberLE(t);

    const w = calcBNComputeWLikeHerumi(tAsBigInt);
}

function calcBNComputeWLikeHerumi(t: bigint): bigint {
    const { c1 } = getHerumiConstants();

    // TODO how to compare with zero?
    // if (tAsBigInt == 0n) {
    //     throw new Error("tAsBigInt == 0");
    // }

    // Herumi code: F::sqr(w, t);
    let w = Fp.sqr(t);

    // Herumi code: w += G::b_;
    // TODO: WHY NOT ADD AS BELOW?
    w += G1.CURVE.b;

    // Herumi code: *w.getFp0() += Fp::one();
    w = Fp.add(w, Fp.ONE);

    // TODO how to compare with zero?
    // if (w == 0n) {
    //     throw new Error("w == 0");
    // }

    // Herumi code: F::inv(w, w);
    w = Fp.inv(w);

    // Herumi code: mulFp(w, c1_);
    w = Fp.mul(w, c1);

    // Herumi code: w *= t;
    w = Fp.mul(w, t);

    return w;
}

function calcBNLoopLikeHerumi(w: bigint, t: bigint): any {
    let x = BigInt(0);
    let y = BigInt(0);

    const legendreOfT = legendreLikeHerumi(t);
    // TODO: Check if this is correct
    const legendreOfTIsNegative = legendreOfT < 0;

    for (let i = 0; i < 3; i++) {
        if (i == 0) {
            x = calcBNLoopLikeHerumiIteration0(w, t);
        } else if (i === 1) {
            x = calcBNLoopLikeHerumiIteration1();
        } else if (i === 2) {
            x = calcBNLoopLikeHerumiIteration2();
        }

        // Herumi code: G::getWeierstrass(y, x);
        y = getWeierstrassLikeHerumi(x);

        // Herumi code: if (F::squareRoot(y, y)) { ... }
        try {
            y = Fp.sqrt(y);
        } catch (e) {
            // No solution, go to next iteration.
            continue;
        }

        if (legendreOfTIsNegative) {
            // Herumi code: F::neg(y, y)
            y = Fp.neg(y);
        }

        // Herumi code: P.set(& b, x, y, false);
        return new G1.ProjectivePoint(x, y, BigInt(1));
    }

    throw new Error("Cannot calcBNLoopLikeHerumi");
}

function calcBNLoopLikeHerumiIteration0(w: bigint, t: bigint): bigint {
    const { c2 } = getHerumiConstants();

    // Herumi code:
    // F::mul(x, t, w);
    // F::neg(x, x);
    // *x.getFp0() += c2_;
    let x = Fp.mul(t, w);
    x = Fp.neg(x);

    // TODO: is addition correct?
    x += c2;

    return x;
}

function calcBNLoopLikeHerumiIteration1(): bigint {
    return BigInt(0);
}

function calcBNLoopLikeHerumiIteration2(): bigint {
    return BigInt(0);
}

// Herumi code: (?)
function legendreLikeHerumi(_t: bigint): number {
    // Not implemented. Find alternative in Noble Crypto.
    return -1;
}

// Herumi code: https://github.com/herumi/mcl/blob/v2.00/include/mcl/ec.hpp#L1954
// void getWeierstrass(Fp& yy, const Fp& x)
// {
//     Fp t;
//     Fp::sqr(t, x);
//     t += a_;
//     t *= x;
//     Fp::add(yy, t, b_);
// }
function getWeierstrassLikeHerumi(x: bigint): bigint {
    const a = Fp.ZERO;
    const b = nobleBls.G1.CURVE.b;

    let t = Fp.sqr(x);
    t = Fp.add(t, a);
    t = Fp.mul(t, x);
    const yy = Fp.add(t, b);
    return yy;
}

// Herumi code: https://github.com/herumi/mcl/blob/v2.00/include/mcl/bn.hpp#L475
// void initBLS12(const mpz_class& z, int curveType) { ... }
// const char *c1 = "be32ce5fbeed9ca374d38c0ed41eefd5bb675277cdf12d11bc2fb026c41400045c03fffffffdfffd";
// const char *c2 = "5f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe";
function getHerumiConstants() {
    const c1Bytes = Buffer.from(
        "fdfffdffffff035c040014c426b02fbc112df1cd775267bbd5ef1ed40e8cd374a39cedbe5fce32be0000000000000000",
        "hex",
    );
    const c2Bytes = Buffer.from(
        "fefffeffffff012e02000a6213d817de8896f8e63ba9b3ddea770f6a07c669ba51ce76df2f67195f0000000000000000",
        "hex",
    );
    const c1 = nobleUtils.bytesToNumberLE(c1Bytes);
    const c2 = nobleUtils.bytesToNumberLE(c2Bytes);

    return { c1, c2 };
}

// We don't directly use Noble Crypto's toBytes(), since that handles not only the "compressed" flag, but also the flags "infinity" and "sort",
// which aren't handled in Herumi's implementation.
// See: https://github.com/paulmillr/noble-curves/blob/1.6.0/src/bls12-381.ts#L382
function projectivePointToBytesLikeHerumi(point: any): Uint8Array {
    const bytesCompressed = nobleUtils.numberToBytesBE(point.px, Fp.BYTES);
    bytesCompressed[0] |= 0b1000_0000;
    bytesCompressed.reverse();
    return bytesCompressed;
}
