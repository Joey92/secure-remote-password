import { Params } from "./lib/params";
import { modPow, randomBigInt } from "./lib/util";

export interface Ephemeral {
  public: bigint;
  secret: bigint;
}

export interface Session {
  key: bigint;
  proof: bigint;
}

export const server = (params: Params) => {
  const { N, g, k, H } = params;

  return {
    generateEphemeral(verifier: bigint): Ephemeral {
      // B = kv + g^b             (b = random number)
      const b = randomBigInt(params.hashOutputBytes);
      const B = k * verifier + (modPow(g, b, N) % N);

      return {
        secret: b,
        public: B,
      };
    },

    deriveSession(
      serverSecretEphemeral: bigint,
      clientPublicEphemeral: bigint,
      salt: bigint,
      username: string,
      verifier: bigint,
      clientSessionProof: bigint
    ): Session {
      // b    Secret ephemeral values
      // A    Public ephemeral values
      // s    User's salt
      // p    Cleartext Password
      // I    Username
      // v    Password verifier
      const b = serverSecretEphemeral;
      const A = clientPublicEphemeral;
      const s = salt;
      const I = String(username);

      // B = kv + g^b             (b = random number)
      const B = k * verifier + (modPow(g, b, N) % N);

      // A % N > 0
      if (A % N == 0n) {
        // fixme: .code, .statusCode, etc.
        throw new Error("The client sent an invalid public ephemeral");
      }

      // u = H(A, B)
      const u = H(A, B);

      // S = (Av^u) ^ b              (computes session key)
      const S = modPow(A * modPow(verifier, u, N), b, N);

      // K = H(S)
      const K = H(S);

      // M = H(H(N) xor H(g), H(I), s, A, B, K)
      const M = H(H(N) ^ H(g), H(I), s, A, B, K);

      const expected = M;
      const actual = BigInt(clientSessionProof);

      if (actual != expected) {
        // fixme: .code, .statusCode, etc.
        throw new Error("Client provided session proof is invalid");
      }

      // P = H(A, M, K)
      const P = H(A, M, K);

      return {
        key: K,
        proof: P,
      };
    },
  };
};

export default server;
