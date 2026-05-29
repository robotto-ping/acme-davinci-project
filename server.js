const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const session = require('express-session');
require('dotenv').config();

const app = express();

app.disable('x-powered-by');
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const REGION = process.env.DV_REGION || 'eu';
const API_ROOT = `https://auth.pingone.${REGION}`;
const ORCHESTRATE_BASE_URL = `https://orchestrate-api.pingone.${REGION}/v1`;
const SESSION_COOKIE_NAME = '__Host-acme_session';
const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS || 30 * 60 * 1000);
const AUTH_FLOW_START_TTL_MS = Number(process.env.AUTH_FLOW_START_TTL_MS || 15 * 1000);
const AUTH_TRANSACTION_TTL_MS = Number(process.env.AUTH_TRANSACTION_TTL_MS || 5 * 60 * 1000);

const REQUIRED_ENV = [
    'DV_COMPANY_ID',
    'DV_API_KEY',
    'WIDGET_POLICY_ID',
    'SESSION_SECRET',
    'PUBLIC_URL',
    'DAVINCI_CALLBACK_SECRET',
    'OIDC_AUDIENCE'
];

const missingEnv = REQUIRED_ENV.filter((key) => !process.env[key]);
if (missingEnv.length > 0) {
    throw new Error(`Missing required environment variables: ${missingEnv.join(', ')}`);
}

if (process.env.SESSION_SECRET.length < 32) {
    throw new Error('SESSION_SECRET must be at least 32 characters long.');
}

if (!Number.isFinite(SESSION_TTL_MS) || SESSION_TTL_MS < 60 * 1000) {
    throw new Error('SESSION_TTL_MS must be at least 60000 milliseconds.');
}

if (!Number.isFinite(AUTH_FLOW_START_TTL_MS) || AUTH_FLOW_START_TTL_MS < 1000) {
    throw new Error('AUTH_FLOW_START_TTL_MS must be at least 1000 milliseconds.');
}

if (!Number.isFinite(AUTH_TRANSACTION_TTL_MS) || AUTH_TRANSACTION_TTL_MS <= AUTH_FLOW_START_TTL_MS) {
    throw new Error('AUTH_TRANSACTION_TTL_MS must be greater than AUTH_FLOW_START_TTL_MS.');
}

const COMPANY_ID = process.env.DV_COMPANY_ID;
const API_KEY = process.env.DV_API_KEY;
const WIDGET_POLICY_ID = process.env.WIDGET_POLICY_ID;
const DAVINCI_CALLBACK_SECRET = process.env.DAVINCI_CALLBACK_SECRET;
const OIDC_ISSUER = process.env.OIDC_ISSUER || `${API_ROOT}/${COMPANY_ID}/as`;
const OIDC_AUDIENCE = process.env.OIDC_AUDIENCE;
const OIDC_JWKS_URI = process.env.OIDC_JWKS_URI || `${OIDC_ISSUER}/jwks`;

const authTransactions = new Map();
let remoteJwks;

const fetchJson = global.fetch
    ? global.fetch.bind(global)
    : (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

function normalizeOrigin(value) {
    if (!value) return null;
    return new URL(value.trim()).origin;
}

function buildAllowedOrigins() {
    const configuredOrigins = [
        process.env.PUBLIC_URL,
        ...(process.env.ALLOWED_ORIGINS || '').split(',')
    ];

    if (process.env.NODE_ENV === 'development') {
        configuredOrigins.push(`http://localhost:${PORT}`, `http://127.0.0.1:${PORT}`);
    }

    const origins = new Set();
    for (const value of configuredOrigins) {
        if (!value || !value.trim()) continue;
        origins.add(normalizeOrigin(value));
    }

    return origins;
}

const allowedOrigins = buildAllowedOrigins();

const logger = (step, message, data = null) => {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] [${step}] ${message}`);
    if (data) console.log(`[${step}] DATA:`, JSON.stringify(redactSensitiveData(data), null, 2));
};

const SENSITIVE_KEYS = new Set([
    'access_token',
    'refresh_token',
    'id_token',
    'sessiontoken',
    'dv_session_token',
    'token',
    'apikey',
    'authorization',
    'x-sk-api-key'
]);

function redactSensitiveData(value) {
    if (Array.isArray(value)) return value.map(redactSensitiveData);
    if (!value || typeof value !== 'object') return value;

    return Object.fromEntries(Object.entries(value).map(([key, val]) => {
        if (SENSITIVE_KEYS.has(key.toLowerCase())) return [key, '[REDACTED]'];
        return [key, redactSensitiveData(val)];
    }));
}

function getRequestOrigin(req) {
    const origin = req.get('Origin');
    if (origin) return normalizeOrigin(origin);

    const referer = req.get('Referer');
    if (referer) return normalizeOrigin(referer);

    return null;
}

function requireTrustedOrigin(req, res, next) {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();

    let requestOrigin = null;
    try {
        requestOrigin = getRequestOrigin(req);
    } catch (error) {
        logger('SECURITY', 'Rejected request with malformed origin header.', {
            path: req.originalUrl,
            ip: req.ip,
            origin: req.get('Origin'),
            referer: req.get('Referer')
        });
        return res.status(403).json({ error: 'Forbidden origin' });
    }

    const fetchSite = req.get('Sec-Fetch-Site');
    const safeFetchSite = !fetchSite || ['same-origin', 'same-site', 'none'].includes(fetchSite);

    if (requestOrigin && allowedOrigins.has(requestOrigin) && safeFetchSite) {
        return next();
    }

    logger('SECURITY', 'Rejected request from untrusted origin.', {
        path: req.originalUrl,
        ip: req.ip,
        origin: req.get('Origin') || null,
        referer: req.get('Referer') || null,
        secFetchSite: fetchSite || null
    });

    return res.status(403).json({ error: 'Forbidden origin' });
}

function requireJsonBody(req, res, next) {
    if (!req.is('application/json')) {
        return res.status(415).json({ error: 'Content-Type must be application/json' });
    }

    return next();
}

function rateLimit({ windowMs, max }) {
    const requests = new Map();

    return (req, res, next) => {
        const now = Date.now();
        const key = `${req.ip}:${req.path}`;
        const current = requests.get(key);

        if (!current || current.resetAt <= now) {
            requests.set(key, { count: 1, resetAt: now + windowMs });
            return next();
        }

        current.count += 1;
        if (current.count > max) {
            res.set('Retry-After', Math.ceil((current.resetAt - now) / 1000).toString());
            return res.status(429).json({ error: 'Too many requests' });
        }

        return next();
    };
}

function cleanupExpiredAuthTransactions(now = Date.now()) {
    for (const [transactionID, transaction] of authTransactions.entries()) {
        if (transaction.completeBy <= now) {
            authTransactions.delete(transactionID);
        }
    }
}

function createAuthTransaction() {
    const issuedAt = Date.now();

    return {
        transactionID: crypto.randomUUID(),
        nonce: crypto.randomBytes(32).toString('base64url'),
        issuedAt,
        startBy: issuedAt + AUTH_FLOW_START_TTL_MS,
        completeBy: issuedAt + AUTH_TRANSACTION_TTL_MS,
        status: 'pending'
    };
}

function safeEqual(a, b) {
    const left = Buffer.from(a || '', 'utf8');
    const right = Buffer.from(b || '', 'utf8');
    return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function requireDavinciCallbackSecret(req, res, next) {
    const provided = req.get('X-DaVinci-Callback-Secret');

    if (!safeEqual(provided, DAVINCI_CALLBACK_SECRET)) {
        logger('SECURITY', 'Rejected unauthenticated DaVinci callback.', { ip: req.ip });
        return res.status(401).json({ error: 'Unauthorized callback' });
    }

    return next();
}

async function verifyIdToken(idToken) {
    const { createRemoteJWKSet, jwtVerify } = await import('jose');

    if (!remoteJwks) {
        remoteJwks = createRemoteJWKSet(new URL(OIDC_JWKS_URI));
    }

    const { payload } = await jwtVerify(idToken, remoteJwks, {
        issuer: OIDC_ISSUER,
        audience: OIDC_AUDIENCE
    });

    return payload;
}

async function parseJsonResponse(response, step) {
    const text = await response.text();
    let data = null;

    try {
        data = text ? JSON.parse(text) : {};
    } catch (error) {
        logger(step, 'Upstream returned non-JSON response.', { status: response.status });
        throw new Error('Invalid upstream response');
    }

    if (!response.ok) {
        logger(step, 'Upstream returned an error response.', {
            status: response.status,
            statusText: response.statusText,
            message: data.message || data.error || null
        });
        throw new Error('Upstream request failed');
    }

    return data;
}

function readDeliveredTokens(body) {
    return {
        access_token: body.access_token || body.tokens?.access_token,
        refresh_token: body.refresh_token || body.tokens?.refresh_token,
        id_token: body.id_token || body.tokens?.id_token,
        token_type: body.token_type || body.tokens?.token_type,
        expires_in: body.expires_in || body.tokens?.expires_in
    };
}

function getTransactionIDFromClaims(claims) {
    return claims.bff_transaction_id
        || claims.bffTransactionID
        || claims.bffTransactionId
        || claims.transactionID
        || claims.transactionId
        || claims.transaction_id;
}

function getSafeClaimDiagnostics(claims) {
    const transactionClaimKeys = [
        'bff_transaction_id',
        'bffTransactionID',
        'bffTransactionId',
        'transactionID',
        'transactionId',
        'transaction_id'
    ];

    return {
        availableClaimKeys: Object.keys(claims).sort(),
        transactionClaimsPresent: transactionClaimKeys.filter((key) => claims[key] !== undefined),
        hasNonce: typeof claims.nonce === 'string',
        nonceLength: typeof claims.nonce === 'string' ? claims.nonce.length : 0
    };
}

function getSafeUserClaims(claims) {
    if (!claims) return null;

    return {
        sub: claims.sub,
        email: claims.email,
        name: claims.name,
        given_name: claims.given_name,
        family_name: claims.family_name,
        preferred_username: claims.preferred_username,
        auth_time: claims.auth_time,
        acr: claims.acr,
        amr: claims.amr
    };
}

function regenerateSession(req) {
    return new Promise((resolve, reject) => {
        req.session.regenerate((error) => error ? reject(error) : resolve());
    });
}

function saveSession(req) {
    return new Promise((resolve, reject) => {
        req.session.save((error) => error ? reject(error) : resolve());
    });
}

function destroySession(req) {
    return new Promise((resolve, reject) => {
        if (!req.session) return resolve();
        req.session.destroy((error) => error ? reject(error) : resolve());
    });
}

const sessionCookieOptions = {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    path: '/',
    maxAge: SESSION_TTL_MS
};

const clearSessionCookieOptions = {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    path: '/'
};

app.use((req, res, next) => {
    res.set({
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'same-origin',
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
    });
    next();
});

const apiRateLimit = rateLimit({ windowMs: 60 * 1000, max: 30 });
const authRateLimit = rateLimit({ windowMs: 60 * 1000, max: 10 });
const callbackRateLimit = rateLimit({ windowMs: 60 * 1000, max: 60 });

app.post(
    '/auth/davinci/complete',
    callbackRateLimit,
    express.json({ limit: '20kb' }),
    requireDavinciCallbackSecret,
    async (req, res) => {
        try {
            const { transactionID, nonce, completedAt, interactionId } = req.body || {};

            if (typeof transactionID !== 'string' || !transactionID) {
                return res.status(400).json({ error: 'Missing transactionID' });
            }

            if (typeof nonce !== 'string' || !nonce) {
                return res.status(400).json({ error: 'Missing nonce' });
            }

            const transaction = authTransactions.get(transactionID);
            if (!transaction || transaction.status !== 'pending') {
                return res.status(409).json({ error: 'Unknown or invalid transaction' });
            }

            if (Date.now() > transaction.completeBy) {
                authTransactions.delete(transactionID);
                return res.status(410).json({ error: 'Transaction expired' });
            }

            if (!safeEqual(nonce, transaction.nonce)) {
                logger('SECURITY', 'Rejected DaVinci callback with body nonce mismatch.', { transactionID });
                return res.status(403).json({ error: 'Invalid transaction binding' });
            }

            const tokens = readDeliveredTokens(req.body);
            if (!tokens.id_token) {
                return res.status(400).json({ error: 'Missing id_token' });
            }

            const claims = await verifyIdToken(tokens.id_token);
            const tokenTransactionID = getTransactionIDFromClaims(claims);

            if (!safeEqual(tokenTransactionID, transactionID)) {
                logger('SECURITY', 'Rejected DaVinci callback with ID token transaction mismatch.', {
                    transactionID,
                    tokenTransactionIDPresent: typeof tokenTransactionID === 'string',
                    tokenTransactionIDLength: typeof tokenTransactionID === 'string' ? tokenTransactionID.length : 0,
                    ...getSafeClaimDiagnostics(claims)
                });
                return res.status(403).json({ error: 'Invalid token transaction binding' });
            }

            if (!safeEqual(claims.nonce, transaction.nonce)) {
                logger('SECURITY', 'Rejected DaVinci callback with ID token nonce mismatch.', {
                    transactionID
                });
                return res.status(403).json({ error: 'Invalid token nonce binding' });
            }

            transaction.status = 'tokens_delivered';
            transaction.completedAt = Number.isFinite(Number(completedAt)) ? Number(completedAt) : Date.now();
            transaction.interactionId = interactionId || null;
            transaction.subject = claims.sub;
            transaction.idTokenClaims = claims;
            transaction.tokens = tokens;

            logger('DAVINCI_CALLBACK', 'Accepted token delivery from DaVinci.', {
                transactionID,
                subject: claims.sub,
                interactionId: transaction.interactionId
            });

            return res.json({ received: true });
        } catch (error) {
            logger('DAVINCI_CALLBACK', 'Failed to process DaVinci callback.', {
                message: error.message
            });
            return res.status(400).json({ error: 'Invalid token delivery' });
        }
    }
);

app.use(cors({
    origin(origin, callback) {
        if (!origin) return callback(null, false);

        try {
            return callback(null, allowedOrigins.has(normalizeOrigin(origin)));
        } catch (error) {
            return callback(null, false);
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type'],
    maxAge: 600,
    optionsSuccessStatus: 204
}));

app.use(requireTrustedOrigin);
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    name: SESSION_COOKIE_NAME,
    cookie: sessionCookieOptions
}));
app.use(express.static('public'));

app.post('/dvtoken', apiRateLimit, requireJsonBody, async (req, res) => {
    cleanupExpiredAuthTransactions();
    const authTransaction = createAuthTransaction();

    logger('WIDGET_INIT', 'Starting DaVinci widget transaction.', {
        transactionID: authTransaction.transactionID,
        issuedAt: authTransaction.issuedAt,
        startBy: authTransaction.startBy,
        completeBy: authTransaction.completeBy
    });

    try {
        const response = await fetchJson(`${ORCHESTRATE_BASE_URL}/company/${COMPANY_ID}/sdktoken`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-SK-API-KEY': API_KEY
            },
            body: JSON.stringify({
                policyId: WIDGET_POLICY_ID,
                parameters: {
                    transactionID: authTransaction.transactionID,
                    nonce: authTransaction.nonce,
                    expiresAt: authTransaction.startBy,
                }
            })
        });

        const data = await parseJsonResponse(response, 'WIDGET_INIT');
        if (!data.success || !data.access_token) {
            logger('WIDGET_INIT', 'DaVinci did not return a usable SDK token.', { success: data.success });
            return res.status(502).json({ error: 'Unable to initialize DaVinci widget' });
        }

        req.session.authTransaction = {
            transactionID: authTransaction.transactionID,
            nonce: authTransaction.nonce,
            issuedAt: authTransaction.issuedAt,
            startBy: authTransaction.startBy,
            completeBy: authTransaction.completeBy,
            status: authTransaction.status
        };

        authTransactions.set(authTransaction.transactionID, {
            ...authTransaction,
            sessionID: req.sessionID
        });

        await saveSession(req);

        return res.json({
            token: data.access_token,
            companyId: COMPANY_ID,
            policyId: WIDGET_POLICY_ID,
            apiRoot: API_ROOT
        });
    } catch (error) {
        logger('WIDGET_INIT', 'Failed to initialize DaVinci widget token.', { message: error.message });
        return res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/auth/finalize', authRateLimit, requireJsonBody, async (req, res) => {
    logger('LOGIN_FINALIZE', 'Widget completed. Finalizing BFF session.');

    try {
        const pending = req.session.authTransaction;
        if (!pending?.transactionID || !pending?.nonce) {
            return res.status(409).json({ error: 'No pending authentication transaction' });
        }

        const transaction = authTransactions.get(pending.transactionID);
        if (!transaction) {
            return res.status(409).json({ error: 'Authentication transaction not ready' });
        }

        if (transaction.sessionID !== req.sessionID) {
            logger('SECURITY', 'Rejected finalize request for mismatched browser session.', {
                transactionID: pending.transactionID
            });
            return res.status(403).json({ error: 'Invalid session binding' });
        }

        if (!safeEqual(pending.nonce, transaction.nonce)) {
            logger('SECURITY', 'Rejected finalize request for mismatched nonce.', {
                transactionID: pending.transactionID
            });
            return res.status(403).json({ error: 'Invalid transaction binding' });
        }

        if (Date.now() > transaction.completeBy) {
            authTransactions.delete(pending.transactionID);
            return res.status(410).json({ error: 'Authentication transaction expired' });
        }

        if (transaction.status !== 'tokens_delivered' || !transaction.tokens?.id_token) {
            return res.status(409).json({ error: 'Authentication transaction not complete' });
        }

        const tokens = transaction.tokens;
        const idTokenClaims = transaction.idTokenClaims;
        const user = getSafeUserClaims(idTokenClaims);

        await regenerateSession(req);
        req.session.authenticated = true;
        req.session.user = user;
        req.session.subject = transaction.subject;
        req.session.access_token = tokens.access_token;
        req.session.refresh_token = tokens.refresh_token;
        req.session.id_token = tokens.id_token;
        req.session.id_token_claims = idTokenClaims;
        req.session.authenticatedAt = Date.now();
        await saveSession(req);

        authTransactions.delete(pending.transactionID);

        logger('LOGIN_FINALIZE', 'BFF session persisted. Login complete.', {
            subject: transaction.subject
        });

        return res.json({ result: 'ok', user });
    } catch (error) {
        logger('LOGIN_FINALIZE', 'Failed to finalize login.', { message: error.message });
        return res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/auth/login', authRateLimit, (req, res) => {
    return res.status(410).json({ error: 'Session-token login handoff has been retired' });
});

app.get('/auth/session', apiRateLimit, (req, res) => {
    if (!req.session?.authenticated) {
        return res.status(401).json({ authenticated: false });
    }

    return res.json({
        authenticated: true,
        user: req.session.user || null
    });
});

app.post('/auth/logout', authRateLimit, async (req, res) => {
    logger('LOGOUT', 'Destroying session.');

    try {
        if (req.session?.authTransaction?.transactionID) {
            authTransactions.delete(req.session.authTransaction.transactionID);
        }

        await destroySession(req);
        res.clearCookie(SESSION_COOKIE_NAME, clearSessionCookieOptions);
        res.clearCookie('acme_session', { path: '/' });
        return res.json({ success: true });
    } catch (error) {
        logger('LOGOUT', 'Failed to destroy session.', { message: error.message });
        return res.status(500).json({ error: 'Internal Server Error' });
    }
});

if (require.main === module) {
    app.listen(PORT, () => console.log(`Server backend live on port ${PORT}`));
}

module.exports = app;
