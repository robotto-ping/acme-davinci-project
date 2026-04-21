const express = require('express');
const cors = require('cors');

const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();
app.enable('trust proxy');
const PORT = process.env.PORT || 3000;

// Environment Variables needed in Railway:
// DV_COMPANY_ID, DV_API_KEY, DV_REGION (e.g., 'com', 'eu', 'asia')
const REGION = process.env.DV_REGION || 'eu';
const API_ROOT = `https://auth.pingone.${REGION}`;
const ORCHESTRATE_BASE_URL = `https://orchestrate-api.pingone.${REGION}/v1`;


const session = require('express-session');

app.use(cookieParser());
app.use(express.json());
app.use(express.static('public'));
app.use(session({
    secret: process.env.SESSION_SECRET || 'acme-secret-key', // Use a long random string in Railway
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: true, // Required for HTTPS/Railway
        sameSite: 'strict',
        maxAge: 3600000 // 1 hour
    }
}));

// Secure CORS - Only allow your Railway domain or localhost
app.use(cors({
    origin: process.env.PUBLIC_URL || `http://localhost:${PORT}`,
    credentials: true // Required to handle DaVinci session cookies
}));



app.post('/dvtoken', async (req, res) => {
    try {
        const { policyId } = req.body;
        const companyId = process.env.DV_COMPANY_ID;
        const apiKey = process.env.DV_API_KEY;

        // Construct the body for the SDK Token request
        let body = { policyId: policyId };

        // If a session cookie exists, pass it to maintain continuity
        if (req.cookies['DV-ST']) {
            body.global = { sessionToken: req.cookies['DV-ST'] };
        }

        const response = await fetch(`${ORCHESTRATE_BASE_URL}/company/${companyId}/sdktoken`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-SK-API-KEY': apiKey
            },
            body: JSON.stringify(body)
        });

        const data = await response.json();

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
        console.error("BFF Error:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.post('/auth/login', async (req, res) => {
    try {
        const { sessionToken } = req.body;
        if (!sessionToken) return res.status(400).send("Missing token");
        const policyId = "cb71ac46ae7129de917e631204285f95";
        const companyId = process.env.DV_COMPANY_ID;
        const apiKey = process.env.DV_API_KEY;

        // Construct the body for the SDK Token request
        let body = { policyId: policyId };
        body.global = { sessionToken: sessionToken };

        let response = await fetch(`${ORCHESTRATE_BASE_URL}/company/${companyId}/sdktoken`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-SK-API-KEY': apiKey
            },
            body: JSON.stringify(body)
        });

        const data = await response.json();
        const sdkToken = data.access_token;

        console.debug(sdkToken);

        body = {};
        const authHeader = 'Bearer ' + sdkToken;
        console.debug(authHeader);

        response = await fetch(`${API_ROOT}/${companyId}/davinci/policy/${policyId}/start`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': authHeader
            }//,
            //body: JSON.stringify(body)
        });

        const responsebody = await response.json();

        console.info(responsebody);
        req.session.access_token = responsebody.access_token;
        req.session.id_token = responsebody.id_token;
        req.session.sessionToken = responsebody.sessionToken
        /*req.session.save((err) => {
            if (err) {
                console.error("Session save error:", err);
                return res.status(500).send("Internal Server Error");
            }
            console.debug('Session saved. Token:', req.session.access_token);
            res.json({ result: 'ok' });
        }); */


        res.json({ result: 'ok' });

    } catch (error) {
        console.error("BFF Error:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});


app.get('/auth/status', async (req, res) => {
    try {
        const access_token = req.session.access_token;
        const id_token = req.session.id_token;
        const sessionToken = req.session.sessionToken;
        const clientID = 'ee68d47a-990b-4d18-9f2e-2ac23a0b63e2'
        const secret = 'mD.HbNzATUaNgmRKekmM~ab89IugvGQRJR-SUjbVMLGY_V4YQ9OT85to9lyCn0Aq'
        console.debug('ACCESS TOKEN FROM SESSION')
        console.debug(access_token)
        if (access_token != null) {
            const introspectURI = 'https://auth.pingone.eu/e42b4943-0641-4a9d-ae63-5f9ede418fc1/as/introspect';
            const params = new URLSearchParams();
            const authHeader = Buffer.from(`${clientID}:${secret}`).toString('base64');
            params.append('token', access_token);
            const response = await fetch(introspectURI, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Authorization': `Basic ${authHeader}`
                },
                body: params.toString()
            });
            const data = await response.json();
            if (data.active == true) {
                //we have a valid access token
                res.json({ "valid_token": true });
            } else {
                if (session_token != null) {

                } else {
                    res.json({ "valid_session": false });
                }
            }
        } else {
            res.json({ "error": true });
        }

    } catch (error) {
        console.error("BFF Error:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.listen(PORT, () => console.log(`Acme BFF live on port ${PORT}`));