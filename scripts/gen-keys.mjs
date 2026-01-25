import { generateKeyPair, exportJWK } from "jose";

const { publicKey, privateKey } = await generateKeyPair("EdDSA");

const publicJwk = await exportJWK(publicKey);
const privateJwk = await exportJWK(privateKey);

publicJwk.kid = "bansou-key-1";
privateJwk.kid = "bansou-key-1";

console.log("ATTEST_PUBLIC_JWK=", JSON.stringify(publicJwk));
console.log("ATTEST_PRIVATE_JWK=", JSON.stringify(privateJwk));
