# OAuth and SAML Demo Server

This is a Node.js server that demonstrates OAuth and SAML authentication flows.

## Features

- Implements both Implicit and Authorization Code OAuth flows
- Implements SAML Service Provider functionality
- Uses Passport.js for authentication
- Simple and clean UI to demonstrate the flows
- Session-based authentication
- Profile page to view authentication details

## Setup

1. Install dependencies:
```bash
npm install
```

2. Configure your environment variables in `.env`:
```
PORT=3000
SESSION_SECRET=your_session_secret
CLIENT_ID=your_client_id
CLIENT_SECRET=your_client_secret
CALLBACK_URL=http://localhost:3000/auth/callback
IMPLICIT_CALLBACK_URL=http://localhost:3000/auth/implicit/callback
```

## Keycloak SAML Configuration

### Critical Settings
1. Client Settings:
   - Client ID: `mysaml`
   - Client Protocol: `saml`
   - Root URL: `http://localhost:3000`
   - Valid Redirect URIs: `http://localhost:3000/*`
   - Base URL: `http://localhost:3000`
   - IDP Initiated SSO URL Name: `mysaml`
   - IDP Initiated SSO Relay State: `http://localhost:3000/auth/saml/idp-initiated`
   - Assertion Consumer Service POST Binding URL: `http://localhost:3000/auth/saml/idp-initiated`

2. Name ID Format Settings:
   - Name ID Format: `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent` (default)
   - To use email instead: Set to `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` and enable "Force Name ID Format"

3. SAML Capabilities:
   - Client Signature Required: OFF
   - Force POST Binding: ON
   - Force Name ID Format: OFF (unless using email format)
   - Include AuthnStatement: ON
   - Sign Assertions: ON

### Common Issues and Solutions

1. Redirect Loop:
   - Check Base URL matches your application URL
   - Verify Assertion Consumer Service URL points to correct endpoint
   - Ensure IDP Initiated SSO URL Name matches URL parameter

2. Invalid Token:
   - Verify certificate format in metadata.xml
   - Check clock skew settings
   - Ensure proper signature validation settings

3. Missing Attributes:
   - Add attribute mappers in Keycloak
   - Check attribute names in SAML response
   - Verify user profile has required attributes

4. Name ID Format Issues:
   - First login shows email, subsequent logins show persistent ID (default behavior)
   - To always use email: Set Name ID Format to emailAddress and enable Force Name ID Format

## Running the Server

```bash
node server.js
```

The server will start on port 3000 (or the port specified in your .env file).

## Authentication Flows

### OAuth Flows
1. Authorization Code Flow
2. Implicit Flow

### SAML Flow
1. Service Provider (SP) Initiated Flow
2. Identity Provider (IdP) Initiated Flow

## Security Notes

- Always use HTTPS in production
- Keep your client secrets secure
- Implement proper session management
- Use secure session secrets
- Implement proper error handling
- Regularly rotate certificates
- Monitor SAML response validation
- Keep Keycloak and dependencies updated

