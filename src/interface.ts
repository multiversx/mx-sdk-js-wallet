/**
 * An interface that defines a signable object (e.g. a transaction).
 */
export interface ISignable {
    /**
     * Returns the signable object in its raw form - a sequence of bytes to be signed.
     */
    serializeForSigning(): Buffer;

    /**
     * Applies the computed signature on the object itself.
     *
     * @param signature The computed signature
    */
    applySignature(signature: Buffer): void;
}

export interface IGuardableSignable extends ISignable {
    /**
    * Applies the guardian signature on the transaction.
    *
    * @param guardianSignature The signature, as computed by a guardian.
    */
    applyGuardianSignature(guardianSignature: Buffer): void;
}

