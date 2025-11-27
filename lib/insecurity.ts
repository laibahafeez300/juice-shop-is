import fs from 'node:fs'
import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { type UserModel } from 'models/user'
import jwt from 'jsonwebtoken'
import sanitizeHtmlLib from 'sanitize-html'
import sanitizeFilenameLib from 'sanitize-filename'
import * as utils from './utils'
import bcrypt from 'bcrypt'

// Read keys from environment variables
export const publicKey = process.env.JWT_PUBLIC_KEY || fs.readFileSync('encryptionkeys/jwt.pub', 'utf8')
const privateKey = process.env.JWT_PRIVATE_KEY || fs.readFileSync('encryptionkeys/jwt.key', 'utf8')
const hmacSecret = process.env.HMAC_SECRET || 'default_hmac_secret'

// --- Password Hashing ---
export const hashPassword = async (password: string) => {
  const saltRounds = 12
  return await bcrypt.hash(password, saltRounds)
}

export const verifyPassword = async (password: string, hash: string) => {
  return await bcrypt.compare(password, hash)
}

// --- Input Sanitization ---
export const sanitizeHtml = (html: string) => sanitizeHtmlLib(html)
export const sanitizeFilename = (filename: string) => sanitizeFilenameLib(filename)

// --- JWT Handling ---
export const authorize = (user: object) => {
  return jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })
}

export const verifyToken = (token: string) => {
  try {
    return jwt.verify(token, publicKey)
  } catch {
    return null
  }
}

export const decodeToken = (token: string) => {
  try {
    return jwt.decode(token)
  } catch {
    return null
  }
}

// --- Auth Middleware ---
export const isAuthorized = () => (req: Request, res: Response, next: NextFunction) => {
  const token = utils.jwtFrom(req)
  if (!token) return res.status(401).json({ error: 'Unauthorized' })
  const decoded = verifyToken(token)
  if (!decoded) return res.status(401).json({ error: 'Invalid token' })
  next()
}

// --- HMAC / Deluxe Token ---
export const deluxeToken = (email: string) => {
  return crypto.createHmac('sha256', hmacSecret).update(email + 'deluxe').digest('hex')
}

// --- Roles ---
export const roles = {
  customer: 'customer',
  deluxe: 'deluxe',
  accounting: 'accounting',
  admin: 'admin'
}

// --- Safe Role Middleware ---
export const isAccounting = () => (req: Request, res: Response, next: NextFunction) => {
  const token = utils.jwtFrom(req)
  const decoded = token ? decodeToken(token) : null
  if (decoded?.data?.role === roles.accounting) {
    next()
  } else {
    res.status(403).json({ error: 'Forbidden' })
  }
}

// --- Redirect Allowlist ---
export const redirectAllowlist = new Set([
  'https://github.com/juice-shop/juice-shop',
  'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm'
])

export const isRedirectAllowed = (url: string) => {
  try {
    const parsed = new URL(url)
    return redirectAllowlist.has(parsed.origin)
  } catch {
    return false
  }
}

// --- Coupon / Z85 ---
import * as z85 from 'z85'

export const generateCoupon = (discount: number, date = new Date()) => {
  const coupon = utils.toMMMYY(date) + '-' + discount
  return z85.encode(coupon)
}

export const discountFromCoupon = (coupon?: string) => {
  if (!coupon) return undefined
  const decoded = z85.decode(coupon).toString()
  const parts = decoded.split('-')
  if (parts.length === 2 && utils.toMMMYY(new Date()) === parts[0]) {
    return parseInt(parts[1])
  }
  return undefined
}
