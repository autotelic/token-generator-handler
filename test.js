import test from 'ava'
import { createTokenHandlers } from './index.js'

test.beforeEach((t) => {
  const encryptionKey = 'supersecret'
  const token = ''
  const { generateToken, tokenAuthHandler } = createTokenHandlers({
    encryptionKey,
    getTokenFromRequest: async () => token
  })
})

test('placeholder', async (t) => {
  t.pass()
})
