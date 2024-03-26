import { webcrypto } from "crypto";

//ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString("base64");
}

//Base64 string to ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  var buff = Buffer.from(base64, "base64");
  return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}

// Creates a pair of private / public RSA keys
type GenerateRsaKeyPair = {
  publicKey: webcrypto.CryptoKey;
  privateKey: webcrypto.CryptoKey;
};

export async function generateRsaKeyPair(): Promise<GenerateRsaKeyPair> {
  const { publicKey, privateKey } = await webcrypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: {name: 'SHA-256'},
      },
      true,
      ['encrypt', 'decrypt']
  );
  return { publicKey, privateKey };
}

export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
  const exportKey = await webcrypto.subtle.exportKey('spki', key);
  return arrayBufferToBase64(exportKey);
}

export async function exportPrvKey(
    key: webcrypto.CryptoKey | null
): Promise<string | null> {
  if (!key) return null;
  const exportKey = await webcrypto.subtle.exportKey('pkcs8', key);
  return arrayBufferToBase64(exportKey);
}

export async function importPubKey(
    strKey: string
): Promise<webcrypto.CryptoKey> {
  const binaryKey = base64ToArrayBuffer(strKey);
  return await webcrypto.subtle.importKey('spki', binaryKey, { name: 'RSA-OAEP', hash: { name: 'SHA-256' } }, true, ['encrypt']);
}

export async function importPrvKey(
    strKey: string
): Promise<webcrypto.CryptoKey> {
  const binaryKey = base64ToArrayBuffer(strKey);
  return await webcrypto.subtle.importKey('pkcs8', binaryKey, { name: 'RSA-OAEP', hash: { name: 'SHA-256' } }, true, ['decrypt']);
}

export async function rsaEncrypt(
    b64Data: string,
    strPublicKey: string
): Promise<string> {
  const publicKey = await importPubKey(strPublicKey);
  const data = base64ToArrayBuffer(b64Data);
  const encryptedData = await webcrypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, data);
  return arrayBufferToBase64(encryptedData);
}

export async function rsaDecrypt(
    data: string,
    privateKey: webcrypto.CryptoKey
): Promise<string> {
  const encryptedData = base64ToArrayBuffer(data);
  const decryptedData = await webcrypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, encryptedData);
  return arrayBufferToBase64(decryptedData);
}

export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  return await webcrypto.subtle.generateKey({ name: 'AES-CBC', length: 256 }, true, ['encrypt', 'decrypt']);
}

export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
  const exportedKey = await webcrypto.subtle.exportKey('raw', key);
  return arrayBufferToBase64(exportedKey);
}

export async function importSymKey(
    strKey: string
): Promise<webcrypto.CryptoKey> {
  const binaryKey = base64ToArrayBuffer(strKey);
  return await webcrypto.subtle.importKey('raw', binaryKey, { name: 'AES-CBC' }, true, ['encrypt', 'decrypt']);
}

export async function symEncrypt(
    key: webcrypto.CryptoKey,
    data: string
): Promise<string> {
  const encodedData = new TextEncoder().encode(data);
  const iv = webcrypto.getRandomValues(new Uint8Array(16));
  const encryptedData = await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv },
      key,
      encodedData
  );
  const result = new Uint8Array(iv.length + encryptedData.byteLength);
  result.set(iv);
  result.set(new Uint8Array(encryptedData), iv.length);

  return arrayBufferToBase64(result.buffer);
}

export async function symDecrypt(
    strKey: string,
    encryptedData: string
): Promise<string> {
  const key = await importSymKey(strKey);
  const encryptedDataArray = base64ToArrayBuffer(encryptedData);
  const decryptedDataArray = await crypto.subtle.decrypt(
      { name: 'AES-CBC', iv: new Uint8Array(16) },
      key,
      encryptedDataArray
  );
  const decryptedData = new TextDecoder().decode(decryptedDataArray.slice(16));
  return decryptedData;
}