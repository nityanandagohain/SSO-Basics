# OAuth and SAML Authentication Demo Server

A comprehensive Node.js server demonstrating OAuth and SAML authentication flows with Keycloak integration.

## 🚀 Features

- **OAuth 2.0 Flows**
  - Authorization Code Flow
  - Implicit Flow
  - Token Management
  - Session Handling

- **SAML 2.0 Integration**
  - Service Provider (SP) Initiated Flow
  - Identity Provider (IdP) Initiated Flow
  - SAML Response Validation
  - Attribute Mapping


## 🛠️ Prerequisites

- Node.js (v14 or higher)
- Docker and Docker Compose
- Keycloak Server

## ⚙️ Setup Instructions

### 1. Keycloak Setup

```bash
# Start Keycloak using Docker Compose
docker-compose up -d
```

1. Access Keycloak Admin Console:
   - URL: `http://localhost:8080`
   - Username: `admin`
   - Password: `admin`

2. Import Realm:
   - Go to "Add Realm"
   - Import `realm.json`

3. Configure SAML Client:
   - Navigate to Clients → Create
   - Set Client ID to `mysaml`
   - Set Client Protocol to `saml`
   - Set Root URL to `http://localhost:3000`
   - Set Valid Redirect URIs to `http://localhost:3000/*`
   - Set Base URL to `http://localhost:3000`

4. Generate Keys:
   - Navigate to Clients → `signoz-standard` → Keys
   - Click "Generate" to obtain the client secret for the authorization code flow.

5. Update metadata.xml:
   - Go to realm settings
   - Click on `SAML 2.0 Identity Provider Metadata`
   - Update the metadata from this section.

### 2. Application Setup

1. Install Dependencies:
```bash
npm install
```

2. Configure Environment:
```bash
# Create .env file
PORT=3000
SESSION_SECRET=your_session_secret
CLIENT_ID=your_client_id
CLIENT_SECRET=your_client_secret
CALLBACK_URL=http://localhost:3000/auth/callback
IMPLICIT_CALLBACK_URL=http://localhost:3000/auth/implicit/callback
```

## 🔐 Keycloak SAML Configuration

### Critical Settings

#### Client Configuration
- **Client ID**: `mysaml`
- **Client Protocol**: `saml`
- **Root URL**: `http://localhost:3000`
- **Valid Redirect URIs**: `http://localhost:3000/*`
- **Base URL**: `http://localhost:3000`
- **IDP Initiated SSO URL Name**: `mysaml`
- **IDP Initiated SSO Relay State**: `http://localhost:3000/auth/saml/idp-initiated`
- **Assertion Consumer Service POST Binding URL**: `http://localhost:3000/auth/saml/idp-initiated`

#### Name ID Format
- **Default**: `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`
- **Email Format**: `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`
  - Enable "Force Name ID Format" when using email format

#### SAML Capabilities
- ✅ Include AuthnStatement: ON
- ✅ Sign Assertions: ON
- ❌ Client Signature Required: OFF
- ✅ Force POST Binding: ON
- ❌ Force Name ID Format: OFF (unless using email format)

## 🔄 Authentication Flows

### SAML Flows
1. **SP-Initiated Flow**
   - URL: `http://localhost:3000`
   - Flow: User → SP → IdP → SP → Profile

2. **IdP-Initiated Flow**
   - URL: `http://localhost:8080/realms/dev/protocol/saml/clients/mysaml`
   - Flow: User → IdP → SP → Profile

### OAuth Flows
1. **Authorization Code Flow**
   - URL: `http://localhost:3000/auth/authorization-code`
   - Includes refresh token support

2. **Implicit Flow**
   - URL: `http://localhost:3000/auth/implicit`
   - Direct token issuance

## 🚨 Troubleshooting Guide

### Common Issues

1. **Redirect Loop**
   - Verify Base URL matches application URL
   - Check Assertion Consumer Service URL
   - Confirm IDP Initiated SSO URL Name

2. **Invalid Token**
   - Validate certificate format in metadata.xml
   - Check clock skew settings
   - Verify signature validation settings

3. **Missing Attributes**
   - Configure attribute mappers in Keycloak
   - Verify attribute names in SAML response
   - Check user profile attributes

4. **Name ID Format Issues**
   - First login: Email format
   - Subsequent logins: Persistent ID
   - To force email: Enable "Force Name ID Format"

## 🔒 Security Best Practices

- Use HTTPS in production
- Implement proper session management
- Rotate certificates regularly
- Monitor SAML response validation
- Keep Keycloak and dependencies updated
- Secure client secrets
- Implement proper error handling

## 🏃‍♂️ Running the Server

```bash
# Start the server
node server.js

# Server will be available at
http://localhost:3000
```

## 📚 Additional Resources

- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [SAML 2.0 Specification](http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
- [OAuth 2.0 Specification](https://tools.ietf.org/html/rfc6749)
