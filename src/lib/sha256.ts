import crypto from "node:crypto";

export default function sha256(...args: (string | bigint)[]) {
  const h = crypto.createHash("sha256");

  for (const arg of args) {
    if (typeof arg === "bigint") {
      h.update(Buffer.from(arg.toString(16), "hex"));
      continue;
    }

    if (typeof arg === "string") {
      h.update(arg);
      continue;
    }

    throw new TypeError("Expected string or SRPInteger");
  }

  return BigInt("0x" + h.digest("hex"));
}
