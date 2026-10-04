// api/confirm-reset.js — étape 2 : vérifie le code et enregistre le nouveau mot de passe.
const { getAdmin, findUserByEmail, hashOtp, hashPassword, newSalt, safeEqualHex } = require('../lib/common');

const MAX_ATTEMPTS = 5;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Méthode non autorisée' });
  }

  try {
    const body = req.body || {};
    const email = String(body.email || '').trim();
    const otp = String(body.otp || '').trim();
    const newPassword = String(body.newPassword || '');

    if (!EMAIL_RE.test(email) || !/^\d{6}$/.test(otp)) {
      return res.status(400).json({ code: 'invalid', error: 'Code invalide' });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ code: 'weak_password', error: 'Le mot de passe doit contenir au moins 6 caractères' });
    }

    const admin = getAdmin();
    const db = admin.firestore();

    const userDoc = await findUserByEmail(db, email);
    if (!userDoc) {
      return res.status(400).json({ code: 'invalid', error: 'Code invalide ou expiré' });
    }

    const resetRef = db.collection('password_resets').doc(userDoc.id);

    // Tout se passe dans une transaction : le compteur d'essais ne peut pas
    // être contourné par des requêtes simultanées.
    const result = await db.runTransaction(async (t) => {
      const snap = await t.get(resetRef);
      if (!snap.exists) return { status: 400, code: 'invalid', error: 'Code invalide ou expiré' };

      const reset = snap.data();
      if (Date.now() > reset.expiresAt) {
        t.delete(resetRef);
        return { status: 400, code: 'expired', error: 'Code expiré, demandez-en un nouveau' };
      }
      if (reset.attempts >= MAX_ATTEMPTS) {
        t.delete(resetRef);
        return { status: 429, code: 'too_many', error: 'Trop de tentatives, demandez un nouveau code' };
      }

      if (!safeEqualHex(reset.otpHash, hashOtp(userDoc.id, otp))) {
        t.update(resetRef, { attempts: reset.attempts + 1 });
        return { status: 400, code: 'invalid', error: 'Code incorrect', remaining: MAX_ATTEMPTS - reset.attempts - 1 };
      }

      // Code correct : nouveau mot de passe (même format que l'app) et code consommé.
      const salt = newSalt();
      t.update(userDoc.ref, {
        passwordHash: hashPassword(newPassword, salt),
        salt,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
      t.delete(resetRef);
      return { status: 200, ok: true };
    });

    const { status, ...payload } = result;
    return res.status(status).json(payload);
  } catch (err) {
    console.error('Erreur confirm-reset:', err);
    return res.status(500).json({ code: 'server', error: 'Erreur du serveur, réessayez' });
  }
};
