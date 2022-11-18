import { AddressConfig } from "./interface"

/**
 * The human-readable-part of the bech32 addresses.
 */
export const defaultAddressPrefix = "erd";

export const DefaultAddressConfig: AddressConfig = {
    prefix: defaultAddressPrefix
}
