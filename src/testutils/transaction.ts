import { ISignable } from "../interface";

/**
 * A dummy transaction used in tests.
 */
export class TestTransaction implements ISignable {
    nonce: number = 0;
    value: string = "";
    receiver: string = "";
    gasPrice: number = 0;
    gasLimit: number = 0;
    data: string = "";
    chainID: string = "";
    version: number = 1;
    options: number = 0;

    sender: string = "";
    guardian: string = "";
    guardianSignature: Buffer = Buffer.from("");
    signature: Buffer = Buffer.from("");

    constructor(init?: Partial<TestTransaction>) {
        Object.assign(this, init);
    }

    serializeForSigning(): Buffer {
        const dataEncoded = this.data ? Buffer.from(this.data).toString("base64") : undefined;
        const guardian = this.guardian ? this.guardian : undefined;
        const options = this.options ? this.options : undefined;

        const plainObject = {
            nonce: this.nonce,
            value: this.value,
            receiver: this.receiver,
            sender: this.sender,
            guardian: guardian,
            gasPrice: this.gasPrice,
            gasLimit: this.gasLimit,
            data: dataEncoded,
            chainID: this.chainID,
            options: options,
            version: this.version
        };

        const serialized = JSON.stringify(plainObject);
        return Buffer.from(serialized);
    }

    applySignature(signature: Buffer) {
        this.signature = signature;
    }

    applyGuardianSignature(guardianSignature: Buffer) {
        this.guardianSignature = guardianSignature;
    }

    getSignature(): Buffer {
        return this.signature;
    }

    getGuardianSignature(): Buffer {
        return this.guardianSignature;
    }
}
