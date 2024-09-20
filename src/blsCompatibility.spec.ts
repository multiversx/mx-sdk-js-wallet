import * as nobleUtils from "@noble/curves/abstract/utils";
import { bls12_381 as nobleBls } from "@noble/curves/bls12-381";

describe("test BLS compatibility (noble crypto and herumi)", () => {
    it("test BLS implementations", async function () {
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
