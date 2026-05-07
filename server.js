const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const session = require('express-session');
require('dotenv').config();

const app = express();


app.enable('trust proxy');
const PORT = process.env.PORT || 3000;
const REGION = process.env.DV_REGION || 'eu';
const API_ROOT = `https://auth.pingone.${REGION}`;
const ORCHESTRATE_BASE_URL = `https://orchestrate-api.pingone.${REGION}/v1`;

// This POLICY_ID is the backend DaVinci flow used to obtain tokens 
const POLICY_ID = process.env.DV_POLICY_ID;

if (!POLICY_ID) {
    console.error("CRITICAL: DV_POLICY_ID is not defined in environment variables!");
}


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
        maxAge: 34560000 
    }
}));

app.use(cors({
    origin: process.env.PUBLIC_URL || `http://localhost:${PORT}`,
    credentials: true
}));

app.use(express.static('public'));

const logger = (step, message, data = null) => {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] [${step}] ${message}`);
    if (data) console.log(`[${step}] DATA:`, JSON.stringify(data, null, 2));
};


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

// --- ROUTES ---

app.post('/dvtoken', async (req, res) => {

    const targetPolicy = req.body.policyId; //Policy ID for the front-end (widget) flow
    logger('WIDGET_INIT', `Requesting SDK Token for Policy: ${targetPolicy}`);

    try {
        const companyId = process.env.DV_COMPANY_ID;
        const apiKey = process.env.DV_API_KEY;

        let body = { policyId: targetPolicy };

        const response = await fetch(`${ORCHESTRATE_BASE_URL}/company/${companyId}/sdktoken`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json', 
                'X-SK-API-KEY': apiKey 
            },
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
            headers: {
                'Content-Type': 'application/json',
                'X-SK-API-KEY': apiKey
            },
            body: JSON.stringify({ 
                    policyId: POLICY_ID,
                     global: { sessionToken } 
                    }
                )
        });
        const sdkData = await sdkRes.json();

        logger('LOGIN_HANDOFF', 'Step 2: Calling Policy /start to get OIDC tokens...');

        const startRes = await fetch(`${API_ROOT}/${companyId}/davinci/policy/${POLICY_ID}/start`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${sdkData.access_token}`,
                'User-Agent': req.headers['user-agent']
            }
        });

        const tokens = await startRes.json();
        logger('LOGIN_HANDOFF', 'Step 3: Tokens received. Storing in Session.');
        req.session.access_token = tokens.access_token;
        req.session.refresh_token = tokens.refresh_token;
        req.session.id_token = tokens.id_token;
        req.session.dv_session_token = tokens.sessionToken;
        logger('LOGIN_HANDOFF', JSON.stringify(tokens));

        req.session.save((err) => {
            logger('LOGIN_HANDOFF', 'Session persisted. Login Complete.');
            res.json({ result: 'ok' });
        });

    } catch (error) {
        logger('LOGIN_HANDOFF', 'CRITICAL ERROR', error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.post('/auth/logout', (req, res) => {
    logger('LOGOUT', 'Destroying session.');
    req.session.destroy();
    res.clearCookie('acme_session');
    res.json({ success: true });
});

app.listen(PORT, () => console.log(`Server backend live on port ${PORT}`));