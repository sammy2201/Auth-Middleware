import { Request, Response, NextFunction } from "express";
import jwt, { JwtPayload } from "jsonwebtoken";

// Define a type-safe interface for requests with user
interface AuthenticatedRequest extends Request {
  user?: string | JwtPayload;
}

export function createAuthMiddleware(secretKey: string) {
  if (!secretKey) throw new Error("JWT secret key is required");

  const authenticateUser = (
    req: Request,
    res: Response,
    next: NextFunction
  ): void => {
    const token = req.header("Authorization")?.split(" ")[1];

    if (!token) {
      res.status(401).json({ message: "Access denied. No token provided." });
      return;
    }

    try {
      const decoded = jwt.verify(token, secretKey);
      (req as AuthenticatedRequest).user = decoded;
      next();
    } catch {
      res.status(403).json({ message: "Invalid token" });
    }
  };

  const getUserIdFromToken = (authHeader?: string): string => {
    if (!authHeader || !authHeader.startsWith("Bearer ")) return "";

    const token = authHeader.split(" ")[1];

    try {
      const decoded = jwt.verify(token, secretKey) as { userId: string };
      return decoded.userId;
    } catch {
      return "";
    }
  };

  return { authenticateUser, getUserIdFromToken };
}
