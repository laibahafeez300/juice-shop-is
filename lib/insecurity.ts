// Secure version: Sensitive keys loaded from environment variables

import fs from 'node:fs'
import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { type UserModel } from 'models/user'
import expressJwt from 'express-jwt'
import jwt from 'jsonwebtoken'
import jws from 'jws'
import sanitizeHtmlLib from 'sanitize-html'
import sanitizeFilenameLib from 'sanitize-filename'
import * as utils from './utils'

// Load PUBLIC KEY (same as original)
export const publicKey =
  fs ? fs.readFileSync('encryptionkeys/jwt.pub', 'utf8') : process.env.PUBLIC_KEY || ''

// ❌ OLD (insecure): Hardcoded private key
// const privateKey = "-----BEGIN RSA PRIVATE KEY-----....."

// ✅ NEW (secure): Private Key from environment variable
const privateKey = process.env.PRIVATE_KEY || ''

// ❌ OLD (insecure): Hardcoded HMAC secret
// export const hmac = (data: string) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj').update(data).digest('hex')

// ✅ NEW (secure): HMAC secret from environment variable
export const hmac = (data: string) =>
  crypto.createHmac('sha256', process.env.HMAC_SECRET || '').update(data).digest('hex')

// Authorization using PRIVATE KEY
export const authorize = (user = {}) =>
  jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })

// Verify using PUBLIC KEY (unchanged)
export const verify = (token: string) =>
  token ? (jws.verify as ((token: string, secret: string) => boolean))(token, publicKey) : false

export const decode = (token: string) => {
  return jws.decode(token)?.payload
}

