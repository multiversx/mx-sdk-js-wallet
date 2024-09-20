import * as nobleUtils from "@noble/curves/abstract/utils";
import { bls12_381 as nobleBls } from "@noble/curves/bls12-381";
import { assert } from "chai";

describe("test BLS compatibility (noble crypto and herumi)", () => {
    it("test BLS implementations", async function () {
    });

    it("test getWeierstrassLikeHerumi", async function () {
        const inputHex = "b14695c802ca943acc28d5e47aec2ce163d3004559fc9d2e1659f5f22ca363f96548e504a6f2b9cab57bcce75c4e9309";
        const expectedOutputHex = "fd15a70e718737b6457701e2c134b254d797837f7166300f46360974e3b51ac4d679f7de76d488d52da1c13a3f1bb719";
        const input = nobleUtils.bytesToNumberLE(Buffer.from(inputHex, "hex"));
        const output = getWeierstrassLikeHerumi(input);
        const outputHex = Buffer.from(nobleUtils.numberToBytesLE(output, 48)).toString("hex");
        
        assert.equal(outputHex, expectedOutputHex);
    });
});

// Herumi code: https://github.com/herumi/mcl/blob/v2.00/include/mcl/ec.hpp#L1954
// void getWeierstrass(Fp& yy, const Fp& x)
// {
//     Fp t;
//     Fp::sqr(t, x);
//     t += a_;
//     t *= x;
//     Fp::add(yy, t, b_);
// }
function getWeierstrassLikeHerumi(x: any) {
    const a = nobleBls.fields.Fp.ZERO;
    const b = nobleBls.G1.CURVE.b;
  
    let t = nobleBls.fields.Fp.sqr(x);
    t = nobleBls.fields.Fp.add(t, a);
    t = nobleBls.fields.Fp.mul(t, x);
    const yy = nobleBls.fields.Fp.add(t, b);
    return yy;
}

// Herumi code: https://github.com/herumi/mcl/blob/v2.00/include/mcl/bn.hpp#L475
// void initBLS12(const mpz_class& z, int curveType) { ... }
// const char *c1 = "be32ce5fbeed9ca374d38c0ed41eefd5bb675277cdf12d11bc2fb026c41400045c03fffffffdfffd";
// const char *c2 = "5f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe";
function getHerumiConstants() {
    const c1Bytes = Buffer.from("fdfffdffffff035c040014c426b02fbc112df1cd775267bbd5ef1ed40e8cd374a39cedbe5fce32be0000000000000000", "hex");
    const c2Bytes = Buffer.from("fefffeffffff012e02000a6213d817de8896f8e63ba9b3ddea770f6a07c669ba51ce76df2f67195f0000000000000000", "hex");
    const c1 = nobleUtils.bytesToNumberLE(c1Bytes);
    const c2 = nobleUtils.bytesToNumberLE(c2Bytes);
    
    return { c1, c2 };
}
