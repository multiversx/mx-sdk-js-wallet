import { FpLegendre, isNegativeLE } from "@noble/curves/abstract/modular";
import * as nobleUtils from "@noble/curves/abstract/utils";
import { bls12_381 as nobleBls } from "@noble/curves/bls12-381";
import { sha512 } from "@noble/hashes/sha512";
import { assert } from "chai";

const Fp = nobleBls.fields.Fp;
const Fp12 = nobleBls.fields.Fp12;
const G1 = nobleBls.G1;
const G2 = nobleBls.G2;

describe.only("test BLS compatibility (noble crypto and herumi)", () => {
    before(() => {
        setupG2GeneratorPointsLikeHerumi();
    });

    it("test get public key", async function () {
        assert.equal(
            toHex(
                getPublicKeyBytesForShortSignaturesLikeHerumi(
                    fromHex("7cff99bd671502db7d15bc8abc0c9a804fb925406fbdd50f1e4c17a4cd774247"),
                ),
            ),
            "e7beaa95b3877f47348df4dd1cb578a4f7cabf7a20bfeefe5cdd263878ff132b765e04fef6f40c93512b666c47ed7719b8902f6c922c04247989b7137e837cc81a62e54712471c97a2ddab75aa9c2f58f813ed4c0fa722bde0ab718bff382208",
        );

        assert.equal(
            toHex(
                getPublicKeyBytesForShortSignaturesLikeHerumi(
                    fromHex("caffb9cb3d24451500f26def03cc034ae61978aeef702688c17ad2fd023c2837"),
                ),
            ),
            "f69e71a3f99a3c3ec5454183b33ea776a9e69cbecca81c13218d3f6becb2deeb258e6210e097c6c04d8ff7573a4bd102ca22fd1aee8dac6eba495f2d24849b28cfbafdf748ed33195abd34212bdbb5ca53e21cee30d966e5c11895fd31f51f16",
        );

        assert.equal(
            toHex(
                getPublicKeyBytesForShortSignaturesLikeHerumi(
                    fromHex("6a4451e61581d545b12390bd461bffe7ca3d28943e61647c96c5acfbe2d01721"),
                ),
            ),
            "3471540b7930bf52639acf66f8b98f73b87de782f5881d36e4c4008fd6de4214ccf1be7cbe2d8a1d4452fff453bc2416b8c7ce7ba84d34af58d20570d53aa12f6407125401dd103ffbb8a2d7f90c73639543c4e617a2da20398ad9d3a63c0010",
        );
    });

    it("test sign", async function () {
        let { point, bytes } = { point: null, bytes: Uint8Array.from([]) };

        // (1)
        ({ point, bytes } = signMessage(
            Buffer.from("hello"),
            fromHex("7cff99bd671502db7d15bc8abc0c9a804fb925406fbdd50f1e4c17a4cd774247"),
        ));

        assert.equal(
            toHex(bytes),
            "84fd0a3a9d4f1ea2d4b40c6da67f9b786284a1c3895b7253fec7311597cda3f757862bb0690a92a13ce612c33889fd86",
        );

        assert.deepEqual(
            point,
            new G1.ProjectivePoint(
                BigInt(
                    "1075917197297270438823667124980979079604536643546345831690492377869764230860196328088999257048104512062036330085764",
                ),
                BigInt(
                    "2752102863809775026289891979823712675472849347369958094574438602351786261194612072949837472907472246482608716327027",
                ),
                BigInt("1"),
            ),
        );

        // (2)
        ({ point, bytes } = signMessage(
            Buffer.from("MultiversX"),
            fromHex("7cff99bd671502db7d15bc8abc0c9a804fb925406fbdd50f1e4c17a4cd774247"),
        ));

        assert.equal(
            toHex(bytes),
            "f6e6102fae2c88c26e1194dbc8dfe7731361db65e7f927a67b51fe28db75f2cab3cefec5def449faa26af12598b5a109",
        );

        assert.deepEqual(
            point,
            new G1.ProjectivePoint(
                BigInt(
                    "1482450793447963658715860002115932381939353442260222481654681881718504194663635571898087934545081216510025224218358",
                ),
                BigInt(
                    "919962068442987202442974284059711666909493365278527151319266393641089300315888650888880306770171677910725372243558",
                ),
                BigInt("1"),
            ),
        );

        // (3)
        ({ point, bytes } = signMessage(
            Buffer.from("message to be signed"),
            fromHex("caffb9cb3d24451500f26def03cc034ae61978aeef702688c17ad2fd023c2837"),
        ));

        assert.equal(
            toHex(bytes),
            "aace25fd4beb6626ff1772f12b61861434d02c4c5c6ae8090befc557765d5f46f319ff229acbfc6783363c496af3de06",
        );

        assert.deepEqual(
            point,
            new G1.ProjectivePoint(
                BigInt(
                    "1057528563207676028023471675007908838941908816948083550247582496134098838133926129342771473293159115713044074057386",
                ),
                BigInt(
                    "819383388216466089251030754544623561533944107703129473594279978102892509524555184566123042178198363789606717296010",
                ),
                BigInt("1"),
            ),
        );

        // (4)
        ({ point, bytes } = signMessage(
            Buffer.from("message to be signed"),
            fromHex("6a4451e61581d545b12390bd461bffe7ca3d28943e61647c96c5acfbe2d01721"),
        ));

        assert.equal(
            toHex(bytes),
            "6847485e9cb0ce069825f492071188f616b32a65e2596f078b15a6c0a2d6033206ea42b621cad0559aea9797f1918691",
        );

        assert.deepEqual(
            point,
            new G1.ProjectivePoint(
                BigInt(
                    "2697446633778451652418207690116743078036977488733553393326783157619907016998477975672020203823369897396697075042152",
                ),
                BigInt(
                    "411441134594009551692769132494713679960976197576962287493840318284317560975445224925971779951042315122149124994335",
                ),
                BigInt("1"),
            ),
        );
    });

    it("test bytesG1ToProjectivePoint", async function () {
        let point = null;

        // (1)
        point = bytesG1ToProjectivePoint(
            fromHex("84fd0a3a9d4f1ea2d4b40c6da67f9b786284a1c3895b7253fec7311597cda3f757862bb0690a92a13ce612c33889fd86"),
        );

        assert.deepEqual(
            point,
            new G1.ProjectivePoint(
                BigInt(
                    "1075917197297270438823667124980979079604536643546345831690492377869764230860196328088999257048104512062036330085764",
                ),
                BigInt(
                    "2752102863809775026289891979823712675472849347369958094574438602351786261194612072949837472907472246482608716327027",
                ),
                BigInt("1"),
            ),
        );

        // (2)
        point = bytesG1ToProjectivePoint(
            fromHex("f6e6102fae2c88c26e1194dbc8dfe7731361db65e7f927a67b51fe28db75f2cab3cefec5def449faa26af12598b5a109"),
        );

        assert.deepEqual(
            point,
            new G1.ProjectivePoint(
                BigInt(
                    "1482450793447963658715860002115932381939353442260222481654681881718504194663635571898087934545081216510025224218358",
                ),
                BigInt(
                    "919962068442987202442974284059711666909493365278527151319266393641089300315888650888880306770171677910725372243558",
                ),
                BigInt("1"),
            ),
        );

        // (3)
        point = bytesG1ToProjectivePoint(
            fromHex("aace25fd4beb6626ff1772f12b61861434d02c4c5c6ae8090befc557765d5f46f319ff229acbfc6783363c496af3de06"),
        );

        assert.deepEqual(
            point,
            new G1.ProjectivePoint(
                BigInt(
                    "1057528563207676028023471675007908838941908816948083550247582496134098838133926129342771473293159115713044074057386",
                ),
                BigInt(
                    "819383388216466089251030754544623561533944107703129473594279978102892509524555184566123042178198363789606717296010",
                ),
                BigInt("1"),
            ),
        );

        // (4)
        point = bytesG1ToProjectivePoint(
            fromHex("6847485e9cb0ce069825f492071188f616b32a65e2596f078b15a6c0a2d6033206ea42b621cad0559aea9797f1918691"),
        );

        assert.deepEqual(
            point,
            new G1.ProjectivePoint(
                BigInt(
                    "2697446633778451652418207690116743078036977488733553393326783157619907016998477975672020203823369897396697075042152",
                ),
                BigInt(
                    "411441134594009551692769132494713679960976197576962287493840318284317560975445224925971779951042315122149124994335",
                ),
                BigInt("1"),
            ),
        );
    });

    it("test verify (works)", async function () {
        assert.isTrue(
            verifySignature(
                fromHex(
                    "84fd0a3a9d4f1ea2d4b40c6da67f9b786284a1c3895b7253fec7311597cda3f757862bb0690a92a13ce612c33889fd86",
                ),
                Buffer.from("hello"),
                fromHex(
                    "e7beaa95b3877f47348df4dd1cb578a4f7cabf7a20bfeefe5cdd263878ff132b765e04fef6f40c93512b666c47ed7719b8902f6c922c04247989b7137e837cc81a62e54712471c97a2ddab75aa9c2f58f813ed4c0fa722bde0ab718bff382208",
                ),
            ),
        );

        assert.isTrue(
            verifySignature(
                fromHex(
                    "aace25fd4beb6626ff1772f12b61861434d02c4c5c6ae8090befc557765d5f46f319ff229acbfc6783363c496af3de06",
                ),
                Buffer.from("message to be signed"),
                fromHex(
                    "f69e71a3f99a3c3ec5454183b33ea776a9e69cbecca81c13218d3f6becb2deeb258e6210e097c6c04d8ff7573a4bd102ca22fd1aee8dac6eba495f2d24849b28cfbafdf748ed33195abd34212bdbb5ca53e21cee30d966e5c11895fd31f51f16",
                ),
            ),
        );
    });

    it("test verify (does not work yet, still debugging)", async function () {
        assert.isTrue(
            verifySignature(
                fromHex(
                    "f6e6102fae2c88c26e1194dbc8dfe7731361db65e7f927a67b51fe28db75f2cab3cefec5def449faa26af12598b5a109",
                ),
                Buffer.from("MultiversX"),
                fromHex(
                    "e7beaa95b3877f47348df4dd1cb578a4f7cabf7a20bfeefe5cdd263878ff132b765e04fef6f40c93512b666c47ed7719b8902f6c922c04247989b7137e837cc81a62e54712471c97a2ddab75aa9c2f58f813ed4c0fa722bde0ab718bff382208",
                ),
            ),
        );

        assert.isTrue(
            verifySignature(
                fromHex(
                    "6847485e9cb0ce069825f492071188f616b32a65e2596f078b15a6c0a2d6033206ea42b621cad0559aea9797f1918691",
                ),
                Buffer.from("message to be signed"),
                fromHex(
                    "3471540b7930bf52639acf66f8b98f73b87de782f5881d36e4c4008fd6de4214ccf1be7cbe2d8a1d4452fff453bc2416b8c7ce7ba84d34af58d20570d53aa12f6407125401dd103ffbb8a2d7f90c73639543c4e617a2da20398ad9d3a63c0010",
                ),
            ),
        );
    });

    it("test hashAndMapToG1LikeHerumi", async function () {
        assert.equal(
            toHex(hashAndMapToG1LikeHerumi(Buffer.from("aaaaaaaa"))),
            "05339eae300f121b5f6ddd41d54e2cefaf6a07472f4a87d2f7195f97d67559910ac1ada88f616a49189670db71769f89",
        );

        assert.equal(
            toHex(hashAndMapToG1LikeHerumi(Buffer.from("hello"))),
            "a1ddb026e51f6e477354f63b8b3cb59af7bf6da8e8a61685ab8c83c3c572ef801824318a45d97fc961fc6229ba18428e",
        );

        assert.equal(
            toHex(hashAndMapToG1LikeHerumi(Buffer.from("world"))),
            "c68a746ae5f5675f2f146baaf1126d5355d00006fcaf24bc47ba328cb0e73e4ed4ebc53283c8a0ae5d01023ee1fe8587",
        );

        assert.equal(
            toHex(hashAndMapToG1LikeHerumi(Buffer.from("this is a message"))),
            "d99081a371bef2d6d747b1fea440e377365293a3d2a8cd0529ddab837360184fcc04453e5cea19fdd8d320ee81b44d97",
        );

        assert.equal(
            toHex(hashAndMapToG1LikeHerumi(Buffer.from("MultiversX"))),
            "39f547f252c481ff9f1b465bdb335d03c4e430c8f3da4941a90beb30538b0faf1d240aa5e7fa30c44b738326a2035b18",
        );

        assert.equal(
            toHex(hashAndMapToG1LikeHerumi(Buffer.from("SDK-JS"))),
            "43df809a75f7153cebcc6346701c9c28319456ec9e9dbd39a46e797b07ca6e9145ff15c5c1483868dd57ccc0a8ff2b99",
        );

        assert.equal(
            toHex(hashAndMapToG1LikeHerumi(Buffer.from("lorem ipsum"))),
            "3f456ad872e39d35b857031bb5328f9b1515e5d00d94db210b510e0f83064961c30dbe8fcf7304a298622d857952c682",
        );
    });

    it("test sha512", async function () {
        assert.equal(
            Buffer.from(sha512("hello")).toString("hex"),
            "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043",
        );
    });

    it("test setArrayMaskLikeHerumi", async function () {
        assert.equal(
            toHex(setArrayMaskLikeHerumi(sha512(Buffer.from("aaaaaaaa")))),
            "f74f2603939a53656948480ce71f1ce466685b6654fd22c61c1f2ce4e2c96d1cd02d162b560c4beaf1ae45f3471dc50b",
        );

        assert.equal(
            toHex(setArrayMaskLikeHerumi(sha512(Buffer.from("hello")))),
            "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c50a",
        );
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
        const outputHex = Buffer.from(projectivePointG1ToBytes(output)).toString("hex");

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

    it("test legendreLikeHerumi", async function () {
        assert.equal(
            legendreLikeHerumi(
                BigInt(
                    "1947061557619909257923000199957305913149841919217032399369035888886860867324583869022231864956010426593339565155799",
                ),
            ),
            1,
        );

        assert.equal(
            legendreLikeHerumi(
                BigInt(
                    "2287818845157091648072502000506798783829628305119603561063065856040047081993849512757193454722385904601543331168919",
                ),
            ),
            -1,
        );

        assert.equal(
            legendreLikeHerumi(
                BigInt(
                    "2070452443764583481186658592096648212376618667920360235487557759555714167455481586459773229376884059003467086956271",
                ),
            ),
            1,
        );

        assert.equal(
            legendreLikeHerumi(
                BigInt(
                    "3066392673129170662178293883062051604774809620215180153438624189323843912738694122128372094104009713090321523946449",
                ),
            ),
            -1,
        );
    });

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
});

function setupG2GeneratorPointsLikeHerumi() {
    (<any>nobleBls).G2.CURVE.Gx.c0 = BigInt(
        "0xf3d011af81acf00140aab3c122c61bbdf0628db81c37664bdfc828163ce074ee33a1a5ce5488556603bc5d8d9f21ecc",
    );
    (<any>nobleBls).G2.CURVE.Gx.c1 = BigInt(
        "0x171df7a5080f908a16c2658ea90164e28c924c3f0e6655f6d82adca6bfbdfb5f9efca82c1609676fa15cd30396f1a4b3",
    );

    (<any>nobleBls).G2.CURVE.Gy.c0 = BigInt(
        "0x738a4db169d33b52ecdf6470030add6488ec3e8fc746734b9107c5315b6352675479f364fc210e5e46857278215abd1",
    );
    (<any>nobleBls).G2.CURVE.Gy.c1 = BigInt(
        "0x19e96417debc6d686aead20955eacc0c18fa0ec8162a32f18e5e390bee6bc4f3c80be4ba018d7f6b488f2445de040696",
    );
}

function signMessage(message: Uint8Array, secretKey: Uint8Array): { point: any; bytes: Uint8Array } {
    const messagePoint = hashAndMapToG1PointLikeHerumi(message);
    return doSignMessage(messagePoint, secretKey);
}

function doSignMessage(messagePoint: any, secretKey: Uint8Array): { point: any; bytes: Uint8Array } {
    const secretKeyReversed = Buffer.from(secretKey).reverse();
    const scalar = G1.normPrivateKeyToScalar(secretKeyReversed);
    const signaturePoint = messagePoint.multiply(scalar);
    const signature = projectivePointG1ToBytes(signaturePoint);
    return { point: signaturePoint, bytes: signature };
}

// Herumi code: https://github.com/herumi/mcl/blob/v2.00/include/mcl/bn.hpp#L2122
function hashAndMapToG1LikeHerumi(message: Uint8Array): Uint8Array {
    const point = hashAndMapToG1PointLikeHerumi(message);
    const pointBytes = projectivePointG1ToBytes(point);
    return pointBytes;
}

function hashAndMapToG1PointLikeHerumi(message: Uint8Array): any {
    const hash = sha512(message);
    const hashMasked = setArrayMaskLikeHerumi(hash);
    const point = mapToG1LikeHerumi(hashMasked);
    return point;
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

function mapToG1LikeHerumi(t: Uint8Array): any {
    // Herumi code: mapToEc(P, t)                   // https://github.com/herumi/mcl/blob/v2.00/include/mcl/bn.hpp#L599
    //                  >> calcBN<G, F>(P, t)       // https://github.com/herumi/mcl/blob/v2.00/include/mcl/bn.hpp#L565
    let P = calcBNLikeHerumi(t);

    // Herumi code: mulByCofactor(P);                           // https://github.com/herumi/mcl/blob/v2.00/include/mcl/bn.hpp#L600
    //              >>  G1::mulGeneric(Q, P, cofactor_);        // https://github.com/herumi/mcl/blob/v2.00/include/mcl/bn.hpp#L430
    P = P.multiply(G1.CURVE.h);

    return P;
}

// Herumi code: https://github.com/herumi/mcl/blob/v2.00/include/mcl/bn.hpp#L362
// "Indifferentiable hashing to Barreto Naehrig curves" by Pierre-Alain Fouque and Mehdi Tibouchi
// https://www.di.ens.fr/~fouque/pub/latincrypt12.pdf
function calcBNLikeHerumi(t: Uint8Array): any {
    let tAsBigInt = nobleUtils.bytesToNumberLE(t);

    const w = calcBNComputeWLikeHerumi(tAsBigInt);
    const P = calcBNLoopLikeHerumi(w, tAsBigInt);
    return P;
}

function calcBNComputeWLikeHerumi(t: bigint): bigint {
    const { c1 } = getHerumiConstants();

    // Herumi code: if (t.isZero()) return false;
    if (Fp.eql(t, Fp.ZERO)) {
        throw new Error("t == 0");
    }

    // Herumi code: F::sqr(w, t);
    let w = Fp.sqr(t);

    // Herumi code: w += G::b_;
    w += G1.CURVE.b;

    // Herumi code: *w.getFp0() += Fp::one();
    w = Fp.add(w, Fp.ONE);

    // Herumi code: if (w.isZero()) return false;
    if (Fp.eql(w, Fp.ZERO)) {
        throw new Error("w == 0");
    }

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
    const legendreOfTIsNegative = legendreOfT < 0;

    for (let i = 0; i < 3; i++) {
        if (i == 0) {
            x = calcBNLoopLikeHerumiIteration0(w, t);
        } else if (i === 1) {
            x = calcBNLoopLikeHerumiIteration1(x);
        } else if (i === 2) {
            x = calcBNLoopLikeHerumiIteration2(w);
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
    x += c2;

    return x;
}

function calcBNLoopLikeHerumiIteration1(x: bigint): bigint {
    // Herumi code:
    // F::neg(x, x);
    // *x.getFp0() -= Fp::one();

    x = Fp.neg(x);
    x -= Fp.ONE;

    return x;
}

function calcBNLoopLikeHerumiIteration2(w: bigint): bigint {
    // Herumi code:
    // F::sqr(x, w);
    // F::inv(x, x);
    // *x.getFp0() += Fp::one();

    let x = Fp.sqr(w);
    x = Fp.inv(x);
    x += Fp.ONE;

    return x;
}

function legendreLikeHerumi(x: bigint): number {
    let f = Fp;

    const legendre = FpLegendre(f.ORDER);
    const legendreSymbol = legendre(f, x);

    if (f.eql(legendreSymbol, f.ZERO)) {
        return 0;
    }

    if (f.eql(legendreSymbol, f.ONE)) {
        return 1;
    }

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
// This works for "G1" points. It does not work for "G2" points.
function projectivePointG1ToBytes(point: any): Uint8Array {
    const bytesCompressed = nobleUtils.numberToBytesBE(point.px, Fp.BYTES);

    // Question for review: is this correct? We set the "compressed" flag for negative y values.
    if (isNegativeLE(point.py, Fp.ORDER)) {
        bytesCompressed[0] |= 0b1000_0000;
    }

    bytesCompressed.reverse();
    return bytesCompressed;
}

function verifySignature(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array) {
    const signatureReversed = Buffer.from(signature).reverse();
    const publicKeyReversed = Buffer.from(publicKey).reverse();

    publicKeyReversed[0] |= 0b1000_0000;
    signatureReversed[0] |= 0b1000_0000;

    const signaturePoint = G1.ProjectivePoint.fromHex(signatureReversed);
    const messagePoint = hashAndMapToG1PointLikeHerumi(message);
    const publicKeyPoint = G2.ProjectivePoint.fromHex(publicKeyReversed);

    return doVerifySignature(signaturePoint, messagePoint, publicKeyPoint);
}

// We cannot directly use Noble Crypto's verifyShortSignatureLikeHerumi(), since that performs its own (standard) hashing and mapping to G1.
// See: https://github.com/paulmillr/noble-curves/blob/main/src/abstract/bls.ts#L420
function doVerifySignature(signaturePoint: any, messagePoint: any, publicKeyPoint: any): boolean {
    const P = publicKeyPoint;
    const Hm = messagePoint;
    const G = G2.ProjectivePoint.BASE;
    const S = signaturePoint;

    const exp = nobleBls.pairingBatch([
        { g1: Hm, g2: P }, // eHmP = pairing(Hm, P, false);
        { g1: S, g2: G.negate() }, // eSG = pairing(S, G.negate(), false);
    ]);

    return Fp12.eql(exp, Fp12.ONE);
}

function getPublicKeyBytesForShortSignaturesLikeHerumi(secretKeyBytes: Uint8Array): Uint8Array {
    const secretKeyReversed = Buffer.from(secretKeyBytes).reverse();
    const publicKey = G2.ProjectivePoint.fromPrivateKey(secretKeyReversed).toRawBytes(false);
    const publicKeyReversed = Buffer.from(publicKey).reverse();
    return publicKeyReversed.subarray(96);
}

function fromHex(input: string): Uint8Array {
    return Buffer.from(input, "hex");
}

function toHex(input: Uint8Array): string {
    return Buffer.from(input).toString("hex");
}
