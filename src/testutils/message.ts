import { ISignable } from "../interface";

/**
 * A dummy message used in tests.
 */
export class TestMessage implements ISignable {
    foo: string = "";
    bar: string = "";
    signature: Buffer = Buffer.from("");

    constructor(init?: Partial<TestMessage>) {
        Object.assign(this, init);
    }

    serializeForSigning(): Buffer {
        let plainObject = {
            foo: this.foo,
            bar: this.bar
        };

        let serialized = JSON.stringify(plainObject);
        return Buffer.from(serialized);
    }

    applySignature(signature: Buffer) {
        this.signature = signature;
    }

    getSignature(): Buffer {
        return this.signature;
    }
}
