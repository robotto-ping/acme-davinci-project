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

const REQUIRED_ENV = [
    'DV_COMPANY_ID',
    'DV_API_KEY',
    'DV_POLICY_ID',
    'WIDGET_POLICY_ID',
    'SESSION_SECRET',
    'PUBLIC_URL'
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

const COMPANY_ID = process.env.DV_COMPANY_ID;
const API_KEY = process.env.DV_API_KEY;
const POLICY_ID = process.env.DV_POLICY_ID;
const WIDGET_POLICY_ID = process.env.WIDGET_POLICY_ID;

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
    'sessionToken',
    'dv_session_token',
    'token',
    'apiKey',
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

function decodeIdToken(token) {
    try {
        if (!token) return null;
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = Buffer.from(base64, 'base64').toString();
        return JSON.parse(jsonPayload);
    } catch (error) {
        logger('DECODE_ERROR', 'Failed to parse ID Token claims.');
        return null;
    }
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

const crypto = require('crypto');

const AUTH_FLOW_START_TTL_MS = Number(
    process.env.AUTH_FLOW_START_TTL_MS || 15 * 1000
);

const AUTH_TRANSACTION_TTL_MS = Number(
    process.env.AUTH_TRANSACTION_TTL_MS || 5 * 60 * 1000
);

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

const apiRateLimit = rateLimit({ windowMs: 60 * 1000, max: 30 });
const authRateLimit = rateLimit({ windowMs: 60 * 1000, max: 10 });

app.post('/dvtoken', apiRateLimit, requireJsonBody, async (req, res) => {
    const authTransaction = createAuthTransaction();

    logger('WIDGET_INIT', 'Starting DaVinci widget transaction.', {
        transactionID: authTransaction.transactionID,
        timestamp: authTransaction.timestamp
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
                    expiresAt: authTransaction.startBy
                }
            })
        });

        const data = await parseJsonResponse(response, 'WIDGET_INIT');
        if (!data.success || !data.access_token) {
            logger('WIDGET_INIT', 'DaVinci did not return a usable SDK token.', {
                success: data.success
            });
            return res.status(502).json({ error: 'Unable to initialize DaVinci widget' });
        }

        req.session.authTransaction = authTransaction;
        await saveSession(req);

        return res.json({
            token: data.access_token,
            companyId: COMPANY_ID,
            policyId: WIDGET_POLICY_ID,
            apiRoot: API_ROOT
        });
    } catch (error) {
        logger('WIDGET_INIT', 'Failed to initialize DaVinci widget token.', {
            message: error.message
        });
        return res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/auth/login', authRateLimit, requireJsonBody, async (req, res) => {
    logger('LOGIN_HANDOFF', 'Widget completed. Starting server-side token exchange.');

    try {
        const { sessionToken } = req.body || {};
        if (typeof sessionToken !== 'string' || sessionToken.length < 10 || sessionToken.length > 4096) {
            return res.status(400).json({ error: 'Invalid session token' });
        }

        const sdkRes = await fetchJson(`${ORCHESTRATE_BASE_URL}/company/${COMPANY_ID}/sdktoken`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-SK-API-KEY': API_KEY
            },
            body: JSON.stringify({
                policyId: POLICY_ID,
                global: { sessionToken }
            })
        });
        const sdkData = await parseJsonResponse(sdkRes, 'LOGIN_HANDOFF');

        if (!sdkData.access_token) {
            logger('LOGIN_HANDOFF', 'DaVinci did not return a backend SDK token.');
            return res.status(502).json({ error: 'Unable to complete login' });
        }

        const startRes = await fetchJson(`${API_ROOT}/${COMPANY_ID}/davinci/policy/${POLICY_ID}/start`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${sdkData.access_token}`,
                'User-Agent': req.headers['user-agent'] || 'unknown'
            }
        });
        const tokens = await parseJsonResponse(startRes, 'LOGIN_HANDOFF');

        if (!tokens.access_token || !tokens.id_token) {
            logger('LOGIN_HANDOFF', 'DaVinci did not return the expected OIDC tokens.');
            return res.status(502).json({ error: 'Unable to complete login' });
        }

        await regenerateSession(req);
        req.session.access_token = tokens.access_token;
        req.session.refresh_token = tokens.refresh_token;
        req.session.id_token = tokens.id_token;
        req.session.dv_session_token = tokens.sessionToken;
        req.session.id_token_claims = decodeIdToken(tokens.id_token);
        await saveSession(req);

        logger('LOGIN_HANDOFF', 'Session persisted. Login complete.');
        return res.json({ result: 'ok' });
    } catch (error) {
        logger('LOGIN_HANDOFF', 'Failed to complete login handoff.', { message: error.message });
        return res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/auth/logout', authRateLimit, async (req, res) => {
    logger('LOGOUT', 'Destroying session.');

    try {
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
