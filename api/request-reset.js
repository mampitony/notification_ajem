// api/request-reset.js — étape 1 : envoie un code à 6 chiffres par email.
//
// Réponse volontairement identique que le compte existe ou non (ou ne soit
// pas encore activé) : on ne révèle pas quels emails sont inscrits.
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { getAdmin, findUserByEmail, hashOtp } = require('../lib/common');

const OTP_TTL_MS = 10 * 60 * 1000;
const RESEND_COOLDOWN_MS = 60 * 1000;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Méthode non autorisée' });
  }

  let resetRef = null;
  try {
    const email = String((req.body && req.body.email) || '').trim();
    if (!EMAIL_RE.test(email)) {
      return res.status(400).json({ error: 'Adresse email invalide' });
    }

    const admin = getAdmin();
    const db = admin.firestore();

    const userDoc = await findUserByEmail(db, email);
    const user = userDoc ? userDoc.data() : null;
    const activated = user && typeof user.passwordHash === 'string' && user.passwordHash.length > 0;

    // Compte inconnu ou non activé : réponse neutre, aucun email envoyé.
    if (!userDoc || !activated) return res.status(200).json({ ok: true });

    resetRef = db.collection('password_resets').doc(userDoc.id);

    // Anti-spam : un seul envoi par minute et par compte.
    const existing = await resetRef.get();
    if (existing.exists) {
      const sentAt = existing.data().sentAt;
      if (sentAt && Date.now() - sentAt < RESEND_COOLDOWN_MS) {
        resetRef = null; // on ne touche pas au code déjà envoyé
        return res.status(200).json({ ok: true });
      }
    }

    const otp = crypto.randomInt(0, 1000000).toString().padStart(6, '0');
    const now = Date.now();
    await resetRef.set({
      otpHash: hashOtp(userDoc.id, otp),
      attempts: 0,
      sentAt: now,
      expiresAt: now + OTP_TTL_MS,
    });

    const gmailUser = process.env.GMAIL_USER;
    const gmailPass = process.env.GMAIL_APP_PASSWORD;
    if (!gmailUser || !gmailPass) throw new Error('GMAIL_USER / GMAIL_APP_PASSWORD manquants');

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: gmailUser, pass: gmailPass },
    });

    const prenom = user.prenom ? ` ${user.prenom}` : '';
    await transporter.sendMail({
      from: `"AJEM" <${gmailUser}>`,
      to: email,
      subject: 'AJEM - Code de réinitialisation du mot de passe',
      text:
        `Bonjour${prenom},\n\n` +
        `Votre code de réinitialisation est : ${otp}\n\n` +
        `Il est valable 10 minutes. Si vous n'avez pas demandé ce code, ignorez ce message : votre mot de passe reste inchangé.`,
      html:
        `<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:24px">` +
        `<h2 style="color:#0163D2;margin:0 0 16px">AJEM</h2>` +
        `<p>Bonjour${prenom},</p>` +
        `<p>Votre code de réinitialisation du mot de passe est :</p>` +
        `<p style="font-size:34px;letter-spacing:8px;font-weight:bold;background:#F1F5FF;padding:16px;text-align:center;border-radius:12px">${otp}</p>` +
        `<p>Il est valable <b>10 minutes</b>.</p>` +
        `<p style="color:#64748B;font-size:13px">Si vous n'avez pas demandé ce code, ignorez ce message : votre mot de passe reste inchangé.</p>` +
        `</div>`,
    });

    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('Erreur request-reset:', err);
    // L'email n'est pas parti : on libère le code pour permettre un nouvel essai.
    if (resetRef) {
      try { await resetRef.delete(); } catch (_) {}
    }
    return res.status(500).json({ error: "Impossible d'envoyer l'email pour le moment" });
  }
};
