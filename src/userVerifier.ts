import { UserPublicKey } from "./userKeys";

interface IAddress {
  pubkey(): Buffer;
}

/**
 * ed25519 signature verification
 */
export class UserVerifier {
  publicKey: UserPublicKey;

  constructor(publicKey: UserPublicKey) {
    this.publicKey = publicKey;
  }

  static fromAddress(address: IAddress): UserVerifier {
    const publicKey = new UserPublicKey(address.pubkey());
    return new UserVerifier(publicKey);
  }

  verify(data: Buffer, signature: Buffer): boolean {
    return this.publicKey.verify(data, signature);
  }
}
