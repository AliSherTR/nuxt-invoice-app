import * as jose from "jose";
import type { EventHandlerRequest, H3Event } from "h3";

export interface AuthUser {
  userId: number;
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
    const secret = new TextEncoder().encode(config.jwtSecret);

    const { payload } = await jose.jwtVerify(token, secret);

    return payload as unknown as AuthUser;
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
    const secret = new TextEncoder().encode(config.jwtSecret);

    const { payload } = await jose.jwtVerify(token, secret);

    return payload as unknown as AuthUser;
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
