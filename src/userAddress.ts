import * as bech32 from "bech32";
import { ErrBadAddress } from "./errors";
import { defaultAddressPrefix } from "./constants";

/**
 * A user Address, as an immutable object.
 */
export class UserAddress {
    private readonly prefix: string;
    private readonly buffer: Buffer;

    public constructor(buffer: Buffer, prefix?: string) {
        this.buffer = buffer;
        this.prefix = prefix || defaultAddressPrefix;
    }

    static fromBech32(value: string): UserAddress {
        let decoded;

        try {
            decoded = bech32.decode(value);
        } catch (err: any) {
            throw new ErrBadAddress(value, err);
        }

        let pubkey = Buffer.from(bech32.fromWords(decoded.words));
        return new UserAddress(pubkey, decoded.prefix);
    }

    /**
     * Returns the hex representation of the address (pubkey)
     */
    hex(): string {
        return this.buffer.toString("hex");
    }

    /**
     * Returns the bech32 representation of the address
     */
    bech32(): string {
        let words = bech32.toWords(this.pubkey());
        let address = bech32.encode(this.prefix, words);
        return address;
    }

    /**
     * Returns the pubkey as raw bytes (buffer)
     */
    pubkey(): Buffer {
        return this.buffer;
    }

    /**
     * Returns the bech32 representation of the address
     */
    toString(): string {
        return this.bech32();
    }

    /**
     * Converts the address to a pretty, plain JavaScript object.
     */
    toJSON(): object {
        return {
            bech32: this.bech32(),
            pubkey: this.hex()
        };
    }
}
