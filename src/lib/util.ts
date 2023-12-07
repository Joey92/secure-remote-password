import crypto from "node:crypto";

export const randomHex = (bytes: number): string =>
  "0x" + crypto.randomBytes(bytes).toString("hex");

export const randomBigInt = (bytes: number) => BigInt(randomHex(bytes));

export function modPow(_base: bigint, _exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let x = _base % mod;
  let exp = _exp;
  while (exp > 0) {
    let leastSignificantBit = exp % 2n;
    exp = exp / 2n;
    if (leastSignificantBit == 1n) {
      result = result * x;
      result = result % mod;
    }
    x = x * x;
    x = x % mod;
  }
  return result;
}
