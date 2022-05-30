import { generateMnemonic, validateMnemonic, mnemonicToSeedSync } from "bip39";
import { UserSecretKey } from "./userKeys";
import { derivePath } from "ed25519-hd-key";
import { ErrWrongMnemonic } from "./errors";

const MNEMONIC_STRENGTH = 256;
const BIP44_DERIVATION_PREFIX = "m/44'/508'/0'/0'";

export class Mnemonic {
    private readonly text: string;

    private constructor(text: string) {
        this.text = text;
    }

    static generate(): Mnemonic {
        let text = generateMnemonic(MNEMONIC_STRENGTH);
        return new Mnemonic(text);
    }

    static fromString(text: string) {
        text = text.trim();

        Mnemonic.assertTextIsValid(text);
        return new Mnemonic(text);
    }

    private static assertTextIsValid(text: string) {
        let isValid = validateMnemonic(text);

        if (!isValid) {
            throw new ErrWrongMnemonic();
        }
    }

    deriveKey(addressIndex: number = 0, password: string = ""): UserSecretKey {
        const seed = mnemonicToSeedSync(this.text, password);
        return this.deriveKeyWithIndex(seed, addressIndex);
    }

    private deriveKeyWithIndex(seed: Buffer, addressIndex: number): UserSecretKey {
        const derivationPath = `${BIP44_DERIVATION_PREFIX}/${addressIndex}'`;
        const derivationResult = derivePath(derivationPath, seed.toString("hex"));
        const key = derivationResult.key;
        return new UserSecretKey(key);
    }

    deriveKeysWithPredicate(options: {
        startAddressIndex: number,
        stopAddressIndex: number,
        numStop: number;
        password?: string,
        predicate: (index: number, userKey: UserSecretKey) => boolean
    }): { index: number, userKey: UserSecretKey }[] {
        const userKeys: { index: number, userKey: UserSecretKey }[] = [];
        const seed = mnemonicToSeedSync(this.text, options.password || "");

        for (let index = options.startAddressIndex; index < options.stopAddressIndex; index++) {
            const userKey = this.deriveKeyWithIndex(seed, index);

            if (options.predicate(index, userKey)) {
                userKeys.push({ index: index, userKey: userKey });
            }

            if (userKeys.length == options.numStop) {
                break;
            }
        }

        return userKeys;
    }

    getWords(): string[] {
        return this.text.split(" ");
    }

    toString(): string {
        return this.text;
    }
}
