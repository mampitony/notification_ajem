// lib/common.js — utilitaires partagés (hors du dossier api/ : non exposé en URL).
const crypto = require('crypto');
const admin = require('firebase-admin');

function getAdmin() {
  if (!admin.apps.length) {
    const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
    if (!raw) throw new Error('Variable FIREBASE_SERVICE_ACCOUNT manquante');
    admin.initializeApp({ credential: admin.credential.cert(JSON.parse(raw)) });
  }
  return admin;
}

// Cherche l'utilisateur par email, exactement comme l'app (champ `email`).
// Essaie la saisie telle quelle, puis en minuscules.
async function findUserByEmail(db, email) {
  const candidates = [email];
  const lower = email.toLowerCase();
  if (lower !== email) candidates.push(lower);

  for (const candidate of candidates) {
    const snap = await db
      .collection('users')
      .where('email', '==', candidate)
      .limit(1)
      .get();
    if (!snap.empty) return snap.docs[0];
  }
  return null;
}

// Empreinte du code : HMAC avec un secret serveur. Un code à 6 chiffres
// n'a que 1 000 000 de possibilités : sans secret, son hash lu dans
// Firestore se casserait en quelques secondes.
function hashOtp(userId, otp) {
  const secret = process.env.OTP_SECRET;
  if (!secret || secret.length < 16) {
    throw new Error('Variable OTP_SECRET manquante (16 caractères minimum)');
  }
  return crypto.createHmac('sha256', secret).update(`${userId}:${otp}`).digest('hex');
}

// Même algorithme que l'app Flutter : sha256(motDePasse + sel) en hexadécimal.
function hashPassword(password, salt) {
  return crypto.createHash('sha256').update(password + salt, 'utf8').digest('hex');
}

function newSalt() {
  return crypto.randomBytes(16).toString('base64url');
}

function safeEqualHex(a, b) {
  const ba = Buffer.from(String(a), 'hex');
  const bb = Buffer.from(String(b), 'hex');
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

module.exports = { getAdmin, findUserByEmail, hashOtp, hashPassword, newSalt, safeEqualHex };
