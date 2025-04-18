# OAuth Demo Server

This is a Node.js server that demonstrates both Implicit and Authorization Code OAuth flows.

## Features

- Implements both Implicit and Authorization Code OAuth flows
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

3. Update the OAuth provider URLs in `server.js`:
- Replace `https://oauth-provider.com/oauth/authorize` with your OAuth provider's authorization URL
- Replace `https://oauth-provider.com/oauth/token` with your OAuth provider's token URL

## Running the Server

```bash
node server.js
```

The server will start on port 3000 (or the port specified in your .env file).

## OAuth Flows

### Authorization Code Flow
1. Click "Authorization Code Flow" on the home page
2. You'll be redirected to the OAuth provider's login page
3. After successful authentication, you'll be redirected back to your profile page

### Implicit Flow
1. Click "Implicit Flow" on the home page
2. You'll be redirected to the OAuth provider's login page
3. After successful authentication, you'll be redirected back to your profile page

## Security Notes

- Always use HTTPS in production
- Keep your client secrets secure
- Implement proper session management
- Use secure session secrets
- Implement proper error handling 