# Mise en ligne de addadollar.com (V4)

Ce guide explique comment brancher l'application sur le domaine, avec HTTPS obligatoire et les vrais paiements Stripe.
Les scripts ne modifient **jamais** le DNS et ne touchent **jamais** à la messagerie (Zimbra : MX, SPF, DKIM, etc.).

## 0. Lis ceci d'abord : ton hébergement OVHcloud

Cette application est un **serveur Node.js** qui doit tourner en permanence : il reçoit les webhooks de Stripe, valide les blocs et publie les blocs payés. Un **hébergement web mutualisé OVHcloud** (cluster129, dossier `www`) sert des fichiers via Apache/PHP. Je n'ai pas pu confirmer qu'il peut faire tourner un serveur Node permanent, et la page Node.js d'OVHcloud ne propose que des **VPS** pour ça.

| Situation | Ce que tu fais |
|---|---|
| Tu as (ou prends) un **VPS** OVHcloud ou autre, avec accès root en SSH | Voie A ci-dessous. C'est la voie recommandée et celle que le script automatise. |
| Tu n'as que l'hébergement mutualisé | Les paiements Stripe ne pourront **pas** fonctionner dessus. Le dossier `deploy/ovh-shared/` contient seulement un `.htaccess` qui force HTTPS pour d'éventuels fichiers statiques. |

L'adresse `51.91.236.255` : si c'est l'IP de ton futur VPS, c'est elle qu'il faut mettre dans les enregistrements DNS. Si c'est l'IP du cluster mutualisé, il faudra à la place l'IP du VPS.

## Voie A : VPS (Debian ou Ubuntu), tout automatique

1. Envoie le dossier du projet sur le serveur (par exemple `scp -r addadollar root@IP_DU_VPS:/root/`), avec son fichier `.env` rempli.
2. En SSH, depuis le dossier du projet :
   ```bash
   cd /root/addadollar
   bash deploy/deploy.sh --dry-run                 # voir ce qui sera fait, sans rien changer
   sudo bash deploy/deploy.sh --email toi@exemple.com
   ```
   Option nginx au lieu de Caddy : `--proxy nginx`. Pare-feu en plus : `--firewall`.
3. Le script :
   - vérifie le `.env` (clés Stripe, clé OpenAI, `BASE_URL`), puis compare le DNS avec l'IP du serveur ;
   - installe Node.js 22 et Caddy (ou nginx + certbot) ;
   - copie l'app dans `/var/www/addadollar`, installe les dépendances, la lance comme service (`addadollar`) ;
   - relie le domaine à l'app, force HTTPS (301), obtient le certificat Let's Encrypt et le renouvelle seul ;
   - teste que `http://` renvoie bien un 301 vers `https://`.
4. Pour mettre à jour plus tard : renvoie les fichiers et relance la même commande. La base `data/` n'est jamais écrasée.

### DNS : ce que tu changes, et rien d'autre

Dans la zone DNS de `addadollar.com` (OVHcloud Manager > Noms de domaine > Zone DNS), modifie **uniquement** :

| Type | Nom | Valeur |
|---|---|---|
| A | `@` (addadollar.com) | IP du VPS |
| A | `www` | IP du VPS |

- S'il existe un enregistrement **AAAA** sur `@` ou `www` qui pointe vers l'ancien hébergement, supprime-le ou remplace-le, sinon les visiteurs en IPv6 arriveront au mauvais endroit.
- **Ne touche pas** aux enregistrements **MX**, **TXT** (SPF, DKIM, DMARC), ni aux **CNAME** `autodiscover`, `autoconfig` ou à tout hôte de messagerie : c'est ta configuration Zimbra.
- La boîte `sufox@addadollar.com` affichée sur la page contact doit exister dans Zimbra.

## Stripe : à faire dans le tableau de bord

1. **Developers > Webhooks > Add endpoint** :
   - URL : `https://addadollar.com/api/stripe/webhook`
   - Événements : `checkout.session.completed`, `checkout.session.async_payment_succeeded`, `checkout.session.expired`
   - Le « signing secret » (`whsec_...`) de ce endpoint doit être la valeur de `STRIPE_WEBHOOK_SECRET` dans `.env`.
2. La clé `rk_live_...` est une clé **restreinte** : elle doit avoir la permission **Checkout Sessions : Write**.
3. Après la mise en ligne, fais **un vrai paiement de 1 $** toi-même, vérifie que le bloc apparaît, puis rembourse-le dans Stripe.

### Comment fonctionne le paiement

1. Le visiteur clique sur « Apply & continue ». Le serveur vérifie le code (sécurité + modération OpenAI) et le met de côté dans la base (`pending`).
2. Le serveur crée une session Stripe Checkout (1 $ ou 3 $, calculé côté serveur) et redirige le visiteur vers la page de paiement de Stripe. La clé secrète ne quitte jamais le serveur.
3. Une fois payé, Stripe appelle le webhook. Le serveur vérifie la signature, le montant et la devise, puis publie le bloc et enregistre la répartition 50 % / 50 %.
4. Un même événement ou une même commande ne peut jamais publier deux blocs (anti-doublon à trois niveaux).
5. Si le visiteur annule, il revient sur l'éditeur avec son code. Rien n'est débité et la commande en attente expire.

`npm run report` affiche les totaux (brut, part charité, part développeur) et les paiements à vérifier à la main.

### Deux choses à savoir sur l'argent

- **La répartition 50 % / 50 % est comptable.** Elle est calculée sur le montant brut payé et enregistrée dans la base. Aucun virement vers l'association n'est fait automatiquement : c'est à toi de le faire.
- **Les frais Stripe pèsent lourd sur 1 $.** Stripe prélève des frais de traitement (aux États-Unis, en général environ 2,9 % + 0,30 $ par paiement par carte, à vérifier selon ton contrat). Sur un paiement de 1 $, il reste environ 0,67 $ ; si 0,50 $ vont à l'association, la part développeur est donc d'environ 0,17 $ avant tes autres coûts.

## Essayer en local avant de mettre en ligne

Le `.env` fourni est celui de la **production** (il redirige tout vers `https://addadollar.com`). Pour tester sur ton ordinateur sans payer, lance :

```bash
NODE_ENV=development PAYMENT_MODE=simulated BASE_URL=http://localhost:3000 FORCE_HTTPS=false TRUST_PROXY=0 npm start
```

Sous Windows (PowerShell) : `$env:NODE_ENV="development"; $env:PAYMENT_MODE="simulated"; $env:BASE_URL="http://localhost:3000"; $env:FORCE_HTTPS="false"; $env:TRUST_PROXY="0"; npm start`

Les variables passées ainsi remplacent celles du `.env`. Le bouton de paiement simulé remplace alors Stripe.

## HTTPS : ce qui est en place

- **Caddy / nginx** : toute requête `http://` reçoit un **301** vers `https://addadollar.com`, `www` est redirigé vers le domaine nu, certificat Let's Encrypt automatique.
- **L'application** (si `NODE_ENV=production`) : redirection 301 de secours pour toute requête non sécurisée, en-tête **HSTS** (`max-age=31536000`), `trust proxy` réglé sur 1 (`TRUST_PROXY=1`) pour lire la vraie IP et le protocole.
- HSTS est envoyé **sans `includeSubDomains`** : sinon il forcerait HTTPS sur tes sous-domaines de messagerie, qui ne le gèrent peut-être pas.

## Si quelque chose ne va pas

| Symptôme | Piste |
|---|---|
| Boucle de redirections | `TRUST_PROXY=1` manquant dans `.env`, ou le proxy n'envoie pas `X-Forwarded-Proto`. |
| Le site ne démarre pas | `journalctl -u addadollar -n 50`. En mode `stripe`, l'appli refuse de démarrer si une clé manque ou si `BASE_URL` n'est pas en `https://`. |
| Pas de certificat | DNS pas encore propagé vers le serveur, ou ports 80/443 fermés. `journalctl -u caddy -n 50`. |
| Paiement fait mais bloc absent | Webhook mal configuré. Regarde Stripe > Webhooks > tentatives, et `npm run report` (section « à vérifier »). |

## Sécurité des clés

- Les clés Stripe et OpenAI sont **uniquement** dans `.env` (droits `600`, exclu de git). Elles ne sont jamais dans le code ni envoyées au navigateur.
- Ces clés ont été écrites dans une conversation : par prudence, **régénère-les** (Stripe : « Roll key », OpenAI : nouvelle clé), mets à jour `.env` et relance le service.
- Ne partage pas l'archive ZIP telle quelle : elle contient le `.env`.
