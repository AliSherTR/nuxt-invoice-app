import * as jose from "jose";
import { PrismaClient } from "~/lib/generated/prisma";

const prisma = new PrismaClient();

export default defineEventHandler(async (event) => {
  try {
    // Only allow GET requests
    if (event.method !== "GET") {
      throw createError({
        statusCode: 405,
        statusMessage: "Method Not Allowed",
      });
    }

    // Get token from cookie
    const token = getCookie(event, "auth-token");
    if (!token) {
      throw createError({
        statusCode: 401,
        statusMessage: "No authentication token found",
      });
    }

    // Verify token using jose
    const config = useRuntimeConfig();
    const secret = new TextEncoder().encode(config.jwtSecret);

    const { payload } = await jose.jwtVerify(token, secret);

    // Extract user data from payload
    const decoded = payload as {
      userId: number;
      email: string;
    };

    // Get user from database
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: {
        id: true,
        name: true,
        email: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!user) {
      throw createError({
        statusCode: 401,
        statusMessage: "User not found",
      });
    }

    return {
      success: true,
      user,
    };
  } catch (error: any) {
    console.error("Get user error:", error);

    // Handle JWT errors from jose
    if (
      error instanceof jose.errors.JWTExpired ||
      error instanceof jose.errors.JWTInvalid ||
      error instanceof jose.errors.JWSInvalid ||
      error instanceof jose.errors.JWTClaimValidationFailed
    ) {
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

    // Handle other errors
    if (error.statusCode) {
      throw error;
    }

    throw createError({
      statusCode: 500,
      statusMessage: "Internal server error",
    });
  } finally {
    await prisma.$disconnect();
  }
});
