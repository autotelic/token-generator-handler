import base64url from 'base64url'

const generateRandomBytes = () =>
  crypto.getRandomValues(new Uint8Array(16))

const fromHexString = hexString =>
  new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)))

const toHexString = bytes =>
  bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '')

const getKey = async (encryptionKey, algo) => {
  return await crypto.subtle.importKey(
    'raw',
    base64url.toBuffer(encryptionKey),
    { name: algo },
    false,
    ['encrypt', 'decrypt']
  )
}

const generateB64Token = async (algo, key, content) => {
  try {
    const key = await getKey(algo)
    const iv = generateRandomBytes()
    const encoder = new TextEncoder()
    const data = encoder.encode(content)
    const encrypted = await crypto.subtle.encrypt({ name: algo, iv }, key, data)
    const b64token = `${toHexString(iv)}${base64url(encrypted)}`
    return { b64token }
  } catch (error) {
    return { error }
  }
}

const createTokenHandlers = async ({
  encryptionKey,
  algo = 'AES-GCM',
  getTokenFromRequest,
}) => {
  const key = await getKey(encryptionKey, algo)

  const generateToken = async (content) => await generateB64Token(algo, key, content)

  const tokenAuthHandler = async (request, env) => {
    const b64token = await getTokenFromRequest(request)
    if (token !== null) {
      try {
        const iv = fromHexString(b64token.slice(0, 32))
        const token = b64token.slice(32)
        const key = await getKey(algo)
        const decrypted = await crypto.subtle.decrypt({ name: algo, iv }, key, base64url.toBuffer(token))
        const decoder = new TextDecoder()
        decoder.decode(decrypted)
        // our token is good so we let the next handler deal with the request
      } catch (e) {
        // we probably want to log the error
        // maybe we allow passing an error handler
      }
    }
    throw new StatusError(401, 'Unauthorized')
  }

  return {
    generateToken,
    tokenAuthHandler
  }
}

export { createTokenHandlers }
