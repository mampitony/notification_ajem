// api/notify.js — serveur d'envoi des notifications push AJEM (Vercel).
//
// L'app Flutter envoie seulement { announcementId }. Ce serveur :
//   1. relit l'annonce dans Firestore (il ne fait pas confiance au texte
//      envoyé par l'app),
//   2. refuse si elle n'existe pas, si elle date de plus de 5 minutes ou
//      si elle a déjà été notifiée (aucun envoi en double / aucun spam
//      avec d'anciennes annonces),
//   3. envoie la notification à tous les appareils abonnés au topic FCM.
const admin = require('firebase-admin');

const TOPIC = 'ajem_announcements';
const MAX_AGE_MS = 5 * 60 * 1000;

function init() {
  if (admin.apps.length) return;
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (!raw) throw new Error('Variable FIREBASE_SERVICE_ACCOUNT manquante');
  admin.initializeApp({ credential: admin.credential.cert(JSON.parse(raw)) });
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Méthode non autorisée' });
  }

  let ref = null;
  try {
    init();

    const id = req.body && req.body.announcementId;
    if (typeof id !== 'string' || !id.trim() || id.includes('/')) {
      return res.status(400).json({ error: 'announcementId invalide' });
    }

    const db = admin.firestore();
    ref = db.collection('announcements').doc(id.trim());

    // Réserve l'annonce de façon atomique : un seul envoi possible.
    const claim = await db.runTransaction(async (t) => {
      const snap = await t.get(ref);
      if (!snap.exists) return { status: 404, error: 'Annonce introuvable' };
      const data = snap.data();
      if (data.notified) return { status: 409, error: 'Déjà notifiée' };
      const created = data.createdAt && data.createdAt.toDate
        ? data.createdAt.toDate().getTime()
        : 0;
      if (!created || Date.now() - created > MAX_AGE_MS) {
        return { status: 403, error: 'Annonce trop ancienne' };
      }
      t.update(ref, { notified: true });
      return { status: 200, data };
    });

    if (claim.status !== 200) {
      ref = null; // rien n'a été réservé
      return res.status(claim.status).json({ error: claim.error });
    }

    const text = String(claim.data.message || '').trim();
    const preview = text.length > 140 ? text.slice(0, 140).trim() + '…' : text;

    await admin.messaging().send({
      topic: TOPIC,
      notification: { title: 'Nouvelle annonce AJEM', body: preview },
      android: { priority: 'high', notification: { sound: 'default' } },
      apns: { payload: { aps: { sound: 'default' } } },
      data: { type: 'announcement', announcementId: id.trim() },
    });

    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('Erreur notify:', err);
    // L'envoi a échoué : libère l'annonce pour qu'un nouvel essai soit possible.
    if (ref) {
      try { await ref.update({ notified: false }); } catch (_) {}
    }
    return res.status(500).json({ error: 'Échec de l\'envoi' });
  }
};
