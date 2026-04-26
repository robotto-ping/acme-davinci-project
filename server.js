const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const session = require('express-session');
require('dotenv').config();

const app = express();

// --- 1. GLOBAL CONFIGURATION ---
app.enable('trust proxy');
const PORT = process.env.PORT || 3000;
const REGION = process.env.DV_REGION || 'eu';
const API_ROOT = `https://auth.pingone.${REGION}`;
const ORCHESTRATE_BASE_URL = `https://orchestrate-api.pingone.${REGION}/v1`;

// NEW: Centralized Policy ID from Environment
const POLICY_ID = process.env.DV_POLICY_ID;

if (!POLICY_ID) {
    console.error("CRITICAL: DV_POLICY_ID is not defined in environment variables!");
}

// --- 2. MIDDLEWARE ---
app.use(express.json());
app.use(cookieParser());

app.use(session({
    secret: process.env.SESSION_SECRET || 'acme-secret-key-12345',
    resave: false,
    saveUninitialized: false,
    name: 'acme_session',
    cookie: {
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        maxAge: 3600000
    }
}));

app.use(cors({
    origin: process.env.PUBLIC_URL || `http://localhost:${PORT}`,
    credentials: true
}));

app.use(express.static('public'));

// --- 3. LOGGING HELPER ---
const logger = (step, message, data = null) => {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] [${step}] ${message}`);
    if (data) console.log(`[${step}] DATA:`, JSON.stringify(data, null, 2));
};

// --- 4. HELPER METHODS ---

/**
 * HELPER: Decodes the payload of a JWT ID Token
 */
function decodeIdToken(token) {
    try {
        if (!token) return null;
        const base64Url = token.split('.')[1]; // Get the payload part
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = Buffer.from(base64, 'base64').toString();
        return JSON.parse(jsonPayload);
    } catch (e) {
        logger('DECODE_ERROR', 'Failed to parse ID Token claims', e);
        return null;
    }
}

async function introspectToken(token) {
    logger('INTROSPECT', 'Calling P1 Introspection endpoint...');
    const introspectURI = `${API_ROOT}/${process.env.DV_COMPANY_ID}/as/introspect`;

    const authHeader = Buffer.from(`${process.env.CLIENT_ID}:${process.env.CLIENT_SECRET}`).toString('base64');

    const params = new URLSearchParams({ token: token });
    const response = await fetch(introspectURI, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': `Basic ${authHeader}`
        },
        body: params.toString()
    });

    logger('INTROSPECT', `Token=: ${token}`);
    logger('INTROSPECT', `Auth header=: ${authHeader}`);

    const data = await response.json();

    logger('INTROSPECT', `data=: ${JSON.stringify(data)}`);
    logger('INTROSPECT', `Result: ${data.active ? 'ACTIVE' : 'INACTIVE'}`);
    return data;
}

async function refreshAccessToken(refreshToken) {
    logger('REFRESH', 'Attempting to refresh Access Token...');
    const tokenURI = `${API_ROOT}/${process.env.DV_COMPANY_ID}/as/token`;
    const authHeader = Buffer.from(`${process.env.CLIENT_ID}:${process.env.CLIENT_SECRET}`).toString('base64');

    const params = new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken
    });

    const response = await fetch(tokenURI, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': `Basic ${authHeader}`
        },
        body: params.toString()
    });

    const data = await response.json();
    if (response.ok) {
        logger('REFRESH', 'Success: New tokens acquired.');
        return data;
    } else {
        logger('REFRESH', 'Failed: Refresh token might be expired.', data);
        return null;
    }
}

async function transparentReauth(dvSessionToken) {
    logger('DV_REAUTH', 'Starting transparent re-auth via DaVinci Session Token...');
    const companyId = process.env.DV_COMPANY_ID;
    const apiKey = process.env.DV_API_KEY;

    // A. Get new SDK Token
    logger('DV_REAUTH', 'Step A: Requesting SDK Token...');
    const sdkRes = await fetch(`${ORCHESTRATE_BASE_URL}/company/${companyId}/sdktoken`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-SK-API-KEY': apiKey },
        body: JSON.stringify({ policyId: POLICY_ID, global: { sessionToken: dvSessionToken } })
    });
    const sdkData = await sdkRes.json();

    if (!sdkData.access_token) {
        logger('DV_REAUTH', 'Failed: Could not get SDK Token.', sdkData);
        return null;
    }

    // B. Execute Policy Start
    logger('DV_REAUTH', 'Step B: Executing Policy Start...');
    const startRes = await fetch(`${API_ROOT}/${companyId}/davinci/policy/${POLICY_ID}/start`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${sdkData.access_token}`
        }
    });

    const tokens = await startRes.json();
    if (startRes.ok) {
        logger('DV_REAUTH', 'Success: New session established via DaVinci.');
        return tokens;
    } else {
        logger('DV_REAUTH', 'Failed: Policy execution error.', tokens);
        return null;
    }
}

// --- 5. ROUTES ---

app.post('/dvtoken', async (req, res) => {
    // Note: We use req.body.policyId if passed, otherwise fallback to our env variable
    const targetPolicy = req.body.policyId || POLICY_ID;
    logger('WIDGET_INIT', `Requesting SDK Token for Policy: ${targetPolicy}`);

    try {
        const companyId = process.env.DV_COMPANY_ID;
        const apiKey = process.env.DV_API_KEY;

        let body = { policyId: targetPolicy };
        if (req.cookies['DV-ST']) {
            logger('WIDGET_INIT', 'Found existing DV-ST cookie, including in request.');
            body.global = { sessionToken: req.cookies['DV-ST'] };
        }

        const response = await fetch(`${ORCHESTRATE_BASE_URL}/company/${companyId}/sdktoken`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-SK-API-KEY': apiKey },
            body: JSON.stringify(body)
        });

        const data = await response.json();
        logger('WIDGET_INIT', 'DaVinci SDK Token Response received.');
        if (!data.success) {
            return res.status(500).json({ error: data.message || "DaVinci Error" });
        }

        // Send the token and config back to the frontend
        res.json({
            token: data.access_token,
            companyId: companyId,
            apiRoot: API_ROOT
        });
    } catch (error) {
        logger('WIDGET_INIT', 'CRITICAL ERROR', error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.post('/auth/login', async (req, res) => {
    logger('LOGIN_HANDOFF', 'Widget completed. Starting server-side token exchange.');
    try {
        const { sessionToken } = req.body;
        const companyId = process.env.DV_COMPANY_ID;
        const apiKey = process.env.DV_API_KEY;

        logger('LOGIN_HANDOFF', 'Step 1: Exchanging Widget sessionToken for SDK Token...');
        const sdkRes = await fetch(`${ORCHESTRATE_BASE_URL}/company/${companyId}/sdktoken`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-SK-API-KEY': apiKey },
            body: JSON.stringify({ policyId: POLICY_ID, global: { sessionToken } })
        });
        const sdkData = await sdkRes.json();

        logger('LOGIN_HANDOFF', 'Step 2: Calling Policy /start to get OIDC tokens...');
        const startRes = await fetch(`${API_ROOT}/${companyId}/davinci/policy/${POLICY_ID}/start`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${sdkData.access_token}`
            }
        });

        const tokens = await startRes.json();
        logger('LOGIN_HANDOFF', 'Step 3: Tokens received. Storing in Session.');
        req.session.access_token = tokens.access_token;
        req.session.refresh_token = tokens.refresh_token;
        req.session.id_token = tokens.id_token;
        req.session.dv_session_token = tokens.sessionToken;

        logger('AFTER LOGIN', 'Token Object from DaVinci');
        logger('AFTER LOGIN', JSON.stringify(tokens));

        req.session.save((err) => {
            logger('LOGIN_HANDOFF', 'Session persisted. Login Complete.');
            res.json({ result: 'ok' });
        });

    } catch (error) {
        logger('LOGIN_HANDOFF', 'CRITICAL ERROR', error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.get('/auth/status', async (req, res) => {
    logger('STATUS_CHECK', 'Waterfall validation started.');
    try {
        let { access_token, refresh_token, dv_session_token } = req.session;


        const sendSuccess = (method, currentIdToken) => {
            const claims = decodeIdToken(currentIdToken);
            return res.json({ 
                valid: true, 
                method: method,
                user: claims // This contains sub, name, email, etc.
            });
        };

        if (access_token) {
            const intro = await introspectToken(access_token);
            if (intro.active) {
                logger('STATUS_CHECK', 'Waterfall Success: Access Token is valid.');
                return sendSuccess("access_token", id_token);
            }
        }

        if (refresh_token) {
            const newData = await refreshAccessToken(refresh_token);
            if (newData && newData.access_token) {
                req.session.access_token = newData.access_token;
                if (newData.refresh_token) req.session.refresh_token = newData.refresh_token;

                return req.session.save(() => {
                    logger('STATUS_CHECK', 'Waterfall Success: Session recovered via Refresh Token.');
                    sendSuccess("refresh_token", req.session.id_token);
                });
            }
        }

        if (dv_session_token) {
            const reauth = await transparentReauth(dv_session_token);
            if (reauth && reauth.access_token) {
                req.session.access_token = reauth.access_token;
                req.session.refresh_token = reauth.refresh_token;
                req.session.id_token = reauth.id_token;
                req.session.dv_session_token = reauth.sessionToken;

                return req.session.save(() => {
                    logger('STATUS_CHECK', 'Waterfall Success: Session recovered via DaVinci Re-auth.');
                    sendSuccess("dv_reauth", req.session.id_token);
                });
            }
        }

        logger('STATUS_CHECK', 'Waterfall Failed: No valid credentials found.');
        res.status(401).json({ valid: false });

    } catch (error) {
        logger('STATUS_CHECK', 'CRITICAL ERROR', error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.post('/auth/logout', (req, res) => {
    logger('LOGOUT', 'Destroying session.');
    req.session.destroy();
    res.clearCookie('acme_session');
    res.json({ success: true });
});

app.listen(PORT, () => console.log(`Acme BFF live on port ${PORT}`));