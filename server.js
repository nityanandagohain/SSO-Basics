require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');
const axios = require('axios');

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

// Add logging middleware
// app.use((req, res, next) => {
//     console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
//     console.log('Query:', req.query);
//     console.log('Body:', req.body);
//     console.log('Session:', req.session);
//     next();
// });

// Routes
app.get('/', (req, res) => {
    console.log('[Home Route]');
    console.log('Session User:', req.session.user);
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
        return res.redirect('/login');
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
        res.redirect('/login');
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

app.get('/profile', (req, res) => {
    if (!req.session.user) {
        console.log('No user found, redirecting to login');
        return res.redirect('/login');
    }
    res.render('profile', { user: req.session.user });
});

app.get('/login', (req, res) => {
    console.log('[Login Route]');
    res.render('login');
});

app.get('/logout', (req, res) => {
    console.log('[Logout Route]');
    console.log('Destroying session for user:', req.session.user);
    
    // Clear all session data
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
        }
        // Clear any cookies
        res.clearCookie('connect.sid');
        // Redirect to home page
        res.redirect('/');
    });
});

// Add middleware to check session
app.use((req, res, next) => {
    // If user is not logged in and trying to access protected routes
    if (!req.session.user && 
        (req.path.startsWith('/profile') || 
         req.path.startsWith('/auth/callback') || 
         req.path.startsWith('/auth/implicit/callback'))) {
        console.log('Unauthorized access attempt to:', req.path);
        return res.redirect('/login');
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