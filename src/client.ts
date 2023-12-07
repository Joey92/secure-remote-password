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

export const client = (params: Params) => {
  const { N, g, k, H, hashOutputBytes } = params;

  return {
    generateSalt: () => randomBigInt(hashOutputBytes),

    derivePrivateKey(salt: bigint, username: string, password: string): bigint {
      // s    User's salt
      // I    Username
      // p    Cleartext Password
      const s = salt;
      const I = username;
      const p = password;

      // x = H(s, H(I | ':' | p))  (s is chosen randomly)
      return H(s, H(`${I}:${p}`));
    },

    deriveVerifier(privateKey: bigint): bigint {
      // v = g^x                   (computes password verifier)
      return modPow(g, privateKey, N);
    },

    generateEphemeral(): Ephemeral {
      // A = g^a                  (a = random number)
      const a = randomBigInt(hashOutputBytes);
      const A = modPow(g, a, N);

      return {
        secret: a,
        public: A,
      };
    },

    deriveSession(
      clientSecretEphemeral: bigint,
      serverPublicEphemeral: bigint,
      salt: bigint,
      username: string,
      privateKey: bigint
    ): Session {
      // a    Secret ephemeral values
      // B    Public ephemeral values
      // s    User's salt
      // I    Username
      // x    Private key (derived from p and s)
      const a = clientSecretEphemeral;
      const B = serverPublicEphemeral;
      const s = salt;
      const I = username;
      const x = privateKey;

      // A = g^a                  (a = random number)
      const A = modPow(g, a, N);

      // B % N > 0
      if (B % N == 0n) {
        // fixme: .code, .statusCode, etc.
        throw new Error("The server sent an invalid public ephemeral");
      }

      // u = H(A, B)
      const u = H(A, B);

      // S = (B - kg^x) ^ (a + ux)
      const S = modPow(B - k * modPow(g, x, N), a + u * x, N);

      // K = H(S)
      const K = H(S);

      // M = H(H(N) xor H(g), H(I), s, A, B, K)
      const M = H(H(N) ^ H(g), H(I), s, A, B, K);

      return {
        key: K,
        proof: M,
      };
    },

    verifySession(
      clientPublicEphemeral: bigint,
      clientSession: Session,
      serverSessionProof: bigint
    ): boolean {
      // A    Public ephemeral values
      // M    Proof of K
      // K    Shared, strong session key
      const A = clientPublicEphemeral;
      const M = clientSession.proof;
      const K = clientSession.key;

      // H(A, M, K)
      const expected = H(A, M, K);

      return serverSessionProof != expected;
    },
  };
};

export default client;
