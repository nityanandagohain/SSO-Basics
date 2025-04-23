require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const xml2js = require('xml2js');
const { DOMParser } = require('xmldom');
const crypto = require('crypto');
const xmlCrypto = require('xml-crypto');
const zlib = require('zlib');
const { promisify } = require('util');

const app = express();


// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // Set to true in production with HTTPS
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: 'lax'
    },
    name: 'oauth-session' // Custom session cookie name
}));

// Routes
app.get('/', (req, res) => {
    // console.log('Session User:', req.session.user);
    res.render('index', { user: req.session.user });
});

// Authorization Code Flow
app.get('/auth/authorization-code', (req, res) => {
    console.log('[Authorization Code Flow Start]');
    const state = Math.random().toString(36).substring(7);
    req.session.oauth2State = state;
    
    const params = new URLSearchParams({
        client_id: process.env.AUTH_CODE_CLIENT_ID,
        response_type: 'code',
        redirect_uri: process.env.AUTH_CODE_CALLBACK_URL,
        scope: 'openid profile',
        state: state
    });

    const authUrl = `http://localhost:8080/realms/dev/protocol/openid-connect/auth?${params.toString()}`;
    console.log('Generated Auth URL:', authUrl);
    console.log('State:', state);
    console.log('Params:', Object.fromEntries(params.entries()));

    res.redirect(authUrl);
});

app.get('/auth/callback', async (req, res) => {
    console.log('[Authorization Code Callback]');
    console.log('Query params:', req.query);
    console.log('Expected state:', req.session.oauth2State);
    
    const { code, state } = req.query;
    
    if (state !== req.session.oauth2State) {
        console.log('State mismatch!');
        console.log('Received:', state);
        console.log('Expected:', req.session.oauth2State);
        return res.redirect('/');
    }

    try {
        console.log('Exchanging code for token...');
        const tokenResponse = await axios.post(
            'http://localhost:8080/realms/dev/protocol/openid-connect/token',
            new URLSearchParams({
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: process.env.AUTH_CODE_CALLBACK_URL,
                client_id: process.env.AUTH_CODE_CLIENT_ID,
                client_secret: process.env.AUTH_CODE_CLIENT_SECRET
            }),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            }
        );

        console.log('Token Response:', tokenResponse.data);
        
        req.session.user = {
            accessToken: tokenResponse.data.access_token,
            refreshToken: tokenResponse.data.refresh_token,
            flowType: 'authorization_code'
        };
        
        res.redirect('/profile');
    } catch (error) {
        console.error('Token exchange error:', error.response?.data || error.message);
        res.redirect('/');
    }
});

// Implicit Flow
app.get('/auth/implicit', (req, res) => {
    console.log('[Implicit Flow Start]');
    const state = Math.random().toString(36).substring(7);
    req.session.oauth2State = state;
    
    const params = new URLSearchParams({
        client_id: process.env.IMPLICIT_CLIENT_ID,
        response_type: 'token',
        redirect_uri: process.env.IMPLICIT_CALLBACK_URL,
        scope: 'openid profile',
        state: state
    });

    const authUrl = `http://localhost:8080/realms/dev/protocol/openid-connect/auth?${params.toString()}`;
    console.log('Generated Auth URL:', authUrl);
    console.log('State:', state);
    console.log('Params:', Object.fromEntries(params.entries()));

    res.redirect(authUrl);
});

app.get('/auth/implicit/callback', (req, res) => {
    console.log('[Implicit Callback]');
    console.log('Query params:', req.query);
    console.log('Expected state:', req.session.oauth2State);
    res.render('handle-implicit', { callbackUrl: process.env.IMPLICIT_CALLBACK_URL });
});

app.post('/auth/implicit/token', (req, res) => {
    console.log('[Implicit Token Received]');
    console.log('Body:', req.body);
    console.log('Session state:', req.session.oauth2State);
    
    const { access_token, state } = req.body;
    
    if (state !== req.session.oauth2State) {
        console.log('State mismatch!');
        console.log('Received:', state);
        console.log('Expected:', req.session.oauth2State);
        return res.status(400).json({ error: 'Invalid state' });
    }

    req.session.user = {
        accessToken: access_token,
        flowType: 'implicit'
    };
    console.log('User session created:', req.session.user);
    res.json({ success: true });
});



// Read SAML IdP metadata
const metadataXml = fs.readFileSync(path.join(__dirname, 'saml-config/metadata.xml'), 'utf8');

// Extract certificate from metadata XML
const certMatch = metadataXml.match(/<ds:X509Certificate>([^<]+)<\/ds:X509Certificate>/);
const certValue = certMatch ? certMatch[1].trim() : null;

// Helper function to format PEM string with proper line breaks
function formatPem(pemString, type) {
    const header = `-----BEGIN ${type}-----\n`;
    const footer = `\n-----END ${type}-----`;
    const body = pemString.replace(/\\n/g, '\n');
    console.log(header + body + footer);
    return header + body + footer;
}

// Format the certificate
const cert = certValue ? formatPem(certValue, 'CERTIFICATE') : null;

if (!cert) {
    throw new Error('Failed to extract certificate from metadata.xml');
}

// Extract SSO URL from metadata
const ssoUrlMatch = metadataXml.match(/SingleSignOnService[^>]+Location="([^"]+)"/);
const ssoUrl = ssoUrlMatch ? ssoUrlMatch[1] : 'http://localhost:8080/realms/dev/protocol/saml';


// SAML Routes
app.get('/auth/saml', (req, res) => {
    const samlRequest = `<?xml version="1.0"?>
        <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            ID="_${crypto.randomBytes(20).toString('hex')}"
            Version="2.0"
            IssueInstant="${new Date().toISOString()}"
            Destination="${ssoUrl}"
            ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            AssertionConsumerServiceURL="http://localhost:3000/auth/saml/callback">
            <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">mysaml</saml:Issuer>
            <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" AllowCreate="true"/>
        </samlp:AuthnRequest>`;
    
    const encodedRequest = Buffer.from(samlRequest).toString('base64');
    
    res.render('saml-redirect', {
        url: ssoUrl,
        samlRequest: encodedRequest,
        relayState: req.query.RelayState || ''
    });
});

// Helper function to validate SAML response
async function validateSamlResponse(samlResponse) {
    try {
        // Decode base64 and decompress if needed
        const decodedResponse = Buffer.from(samlResponse, 'base64');
        let inflatedResponse;
        
        // Check if the response is compressed (starts with 0x78)
        if (decodedResponse[0] === 0x78) {
            try {
                inflatedResponse = await promisify(zlib.inflateRaw)(decodedResponse);
            } catch (error) {
                // If decompression fails, use the decoded response as-is
                inflatedResponse = decodedResponse;
            }
        } else {
            inflatedResponse = decodedResponse;
        }

        // Parse the XML
        const xmlDoc = new DOMParser().parseFromString(inflatedResponse.toString('utf8'), 'text/xml');
        
        // Get the assertion
        const assertion = xmlDoc.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Assertion')[0];
        if (!assertion) {
            throw new Error('No SAML assertion found in response');
        }

        // Get the NameID
        const nameID = assertion.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'NameID')[0];
        if (!nameID) {
            throw new Error('No NameID found in assertion');
        }

        // Get the attribute statement
        const attributeStatement = assertion.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'AttributeStatement')[0];
        if (!attributeStatement) {
            throw new Error('No attribute statement found in assertion');
        }

        // Process attributes
        const attributes = {};
        const attributeNodes = attributeStatement.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Attribute');
        for (let i = 0; i < attributeNodes.length; i++) {
            const attribute = attributeNodes[i];
            const name = attribute.getAttribute('Name');
            const values = attribute.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'AttributeValue');
            if (values.length > 0) {
                attributes[name] = values[0].textContent;
            }
        }

        // Construct the result
        return {
            issuer: assertion.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Issuer')[0].textContent,
            inResponseTo: assertion.getAttribute('InResponseTo'),
            sessionIndex: assertion.getAttribute('SessionIndex'),
            nameID: {
                format: nameID.getAttribute('Format'),
                nameQualifier: nameID.getAttribute('NameQualifier'),
                spNameQualifier: nameID.getAttribute('SPNameQualifier'),
                value: nameID.textContent
            },
            attributes: attributes
        };
    } catch (error) {
        console.error('SAML Validation Error:', error);
        throw error;
    }
}

// SAML callback endpoint
app.post('/auth/saml/callback', async (req, res) => {
    try {
        console.log('=== SAML Callback Request ===');
        console.log('Request Body:', req.body);
        
        const { SAMLResponse } = req.body;
        
        if (!SAMLResponse) {
            console.error('No SAMLResponse found in request');
            return res.redirect('/');
        }
        
        console.log('SAML Response:', SAMLResponse);
        
        const result = await validateSamlResponse(SAMLResponse);
        
        console.log('=== SAML Validation Success ===');
        console.log('User Attributes:', result);
        
        req.session.user = {
            ...result,
            flowType: 'saml'
        };
        
        res.redirect('/profile');
    } catch (error) {
        console.error('SAML Validation Error:', error);
        res.redirect('/');
    }
});

// Add IdP-initiated flow endpoint (POST)
app.post('/auth/saml/idp-initiated',
    express.urlencoded({ extended: false }),
    (req, res, next) => {
        console.log('=== IdP-Initiated POST Request Details ===');
        console.log('Request Method:', req.method);
        console.log('Request URL:', req.url);
        console.log('Request Headers:', req.headers);
        console.log('Request Body:', req.body);
        console.log('Request Query:', req.query);
        console.log('Request Path:', req.path);
        console.log('Request Original URL:', req.originalUrl);
        console.log('Request Base URL:', req.baseUrl);
        console.log('===================================');
        next();
    },
    async (req, res) => {
        try {
            console.log('=== IdP-Initiated POST Authentication ===');
            console.log('Request Body:', req.body);
            
            const samlResponse = req.body.SAMLResponse;
            
            if (!samlResponse) {
                console.error('No SAMLResponse found in request');
                return res.redirect('/');
            }
            
            console.log('SAML Response:', samlResponse);
            
            const result = await validateSamlResponse(samlResponse);
            
            console.log('=== SAML Validation Success ===');
            console.log('User Attributes:', result);
            
            req.session.user = {
                ...result,
                flowType: 'saml-idp-initiated'
            };
            
            res.redirect('/profile');
        } catch (error) {
            console.error('IdP-Initiated POST Authentication Error:', error);
            res.redirect('/');
        }
    }
);

// Profile route
app.get('/profile', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/');
    }
    res.render('profile', { user: req.session.user });
});

app.get('/logout', (req, res) => {
    console.log('[Logout Route]');
    console.log('Destroying session for user:', req.session.user);
    
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
        }
        res.clearCookie('connect.sid');
        res.redirect('/');
    });
});

// Add middleware to check session
app.use((req, res, next) => {
    if (!req.session.user && 
        (req.path.startsWith('/profile') || 
         req.path.startsWith('/auth/callback') || 
         req.path.startsWith('/auth/implicit/callback'))) {
        console.log('Unauthorized access attempt to:', req.path);
        return res.redirect('/');
    }
    next();
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    console.log('Environment variables:');
    console.log('AUTH_CODE_CLIENT_ID:', process.env.AUTH_CODE_CLIENT_ID);
    console.log('IMPLICIT_CLIENT_ID:', process.env.IMPLICIT_CLIENT_ID);
    console.log('AUTH_CODE_CALLBACK_URL:', process.env.AUTH_CODE_CALLBACK_URL);
    console.log('IMPLICIT_CALLBACK_URL:', process.env.IMPLICIT_CALLBACK_URL);
}); 