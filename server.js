const express = require('express');
const cors = require('cors');

const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Environment Variables needed in Railway:
// DV_COMPANY_ID, DV_API_KEY, DV_REGION (e.g., 'com', 'eu', 'asia')
const REGION = process.env.DV_REGION || 'eu';
const API_ROOT = `https://auth.pingone.${REGION}`;
const ORCHESTRATE_BASE_URL = `https://orchestrate-api.pingone.${REGION}/v1`;

app.use(cookieParser());
app.use(express.json());
app.use(express.static('public'));

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

        body = {}; 

        response = await fetch(`${ORCHESTRATE_BASE_URL}/company/${companyId}/policy/${policyId}/start`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer: ' + sdkToken
            },
            body: JSON.stringify(body)
        });

        console.info(response);

        res.json({ message: "Session established" });

    } catch (error) {
        console.error("BFF Error:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.listen(PORT, () => console.log(`Acme BFF live on port ${PORT}`));