# Auth-Middleware

An Express.js middleware for authenticating requests using JSON Web Tokens (JWT), with support for token blacklisting and type-safe request extension.

## ✨ Features

- JWT-based authentication
- Optional token blacklist support (e.g. Redis)
- Secure, type-safe user handling
- Simple utility for extracting user ID from tokens

## 📦 Installation

```bash
npm install @sanmay-sam/auth-middleware
```

## Usage

### 1. Import and Initialize Middleware

```ts
import { createAuthMiddleware } from "@sanmay-sam/auth-middleware";

const { authenticateUser, getUserIdFromToken } = createAuthMiddleware(
  process.env.JWT_SECRET,
  isBlacklisted // optional async function
);
```

### 2. Example Express Integration

```ts
import express from "express";
import { createAuthMiddleware } from "@sanmay-sam/auth-middleware";

const Redis = require("ioredis");
const redis = new Redis();

const isBlacklisted = async (token: string): Promise<boolean> => {
  const result = await redis.get(token);
  return result === "blacklisted";
};

const { authenticateUser } = createAuthMiddleware(
  process.env.JWT_SECRET,
  isBlacklisted
);

const app = express();

app.get("/protected", authenticateUser, (req, res) => {
  res.json({ message: "Authenticated!", user: req.user });
});
```

## 🔐 API

### `createAuthMiddleware(secretKey: string, isBlacklistedFn?: (token: string) => Promise<boolean>)`

Returns:

- `authenticateUser(req, res, next)` – Express middleware to validate tokens.
- `getUserIdFromToken(authHeader?: string): string` – Utility to extract `userId` from a bearer token.

## TypeScript Support

```ts
interface AuthenticatedRequest extends Request {
  user?: string | JwtPayload;
}
```

To use this in your routes, cast `req`:

```ts
(req as AuthenticatedRequest).user;
```

### Logout Endpoint Example

This example shows how to implement a logout route that blacklists JWT tokens using Redis:

````ts
import { Request, Response } from "express";

export const logout = async (req: Request, res: Response): Promise<void> => {
  try {
    if (!req.headers.authorization?.startsWith("Bearer ")) {
      res.status(401).json({ message: "Missing or invalid token" });
      return;
    }
    if (req.headers.authorization) {
      const token = req.headers.authorization.split(" ")[1];
      const expiresIn = 3600; // 1 hour
      await redis.setex(token, expiresIn, "blacklisted");
      res.status(200).json({ message: "Logged out successfully" });
    }
  } catch (error) {
    console.error("Error in logging out:", error);
    res.status(500).json({ message: "Error in logging out" });
  }
};
```

## Example Controller/Router Setup

```ts
router.post("/set-new-password", authenticateUser, forgetPassword);
````

## ⚙️ Environment Variables

- `JWT_SECRET`: your application's JWT secret key (required)

## Issues

Please report issues at [GitHub Issues](https://github.com/sammy2201/Auth-Middleware/issues)

## 🔗 Links

- [GitHub Repository](https://github.com/sammy2201/Auth-Middleware)
- [NPM Package](https://www.npmjs.com/package/@sanmay-sam/auth-middleware)
