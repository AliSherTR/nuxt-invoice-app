import jwt from "jsonwebtoken";
import type { EventHandlerRequest, H3Event } from "h3";

export interface AuthUser {
  userId: string;
  email: string;
}

export async function requireAuth(
  event: H3Event<EventHandlerRequest>
): Promise<AuthUser> {
  const token = getCookie(event, "auth-token");

  if (!token) {
    throw createError({
      statusCode: 401,
      statusMessage: "Authentication required",
    });
  }

  try {
    const config = useRuntimeConfig();
    const decoded = jwt.verify(token, config.jwtSecret) as AuthUser;
    return decoded;
  } catch (error) {
    // Clear invalid token
    setCookie(event, "auth-token", "", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 0,
    });

    throw createError({
      statusCode: 401,
      statusMessage: "Invalid or expired token",
    });
  }
}

export async function getOptionalAuth(
  event: H3Event<EventHandlerRequest>
): Promise<AuthUser | null> {
  const token = getCookie(event, "auth-token");

  if (!token) {
    return null;
  }

  try {
    const config = useRuntimeConfig();
    const decoded = jwt.verify(token, config.jwtSecret) as AuthUser;
    return decoded;
  } catch (error) {
    // Clear invalid token
    setCookie(event, "auth-token", "", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 0,
    });

    return null;
  }
}
