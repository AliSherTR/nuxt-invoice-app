import { d as defineEventHandler, c as createError, g as getCookie, u as useRuntimeConfig, p as prisma, s as setCookie } from '../../../nitro/nitro.mjs';
import * as jose from 'jose';
import 'node:os';
import 'node:tty';
import 'node:fs';
import 'node:path';
import 'node:crypto';
import 'node:child_process';
import 'node:fs/promises';
import 'node:util';
import 'node:process';
import 'node:async_hooks';
import 'node:events';
import 'path';
import 'fs';
import 'node:http';
import 'node:https';
import 'node:buffer';
import 'node:url';
import 'ipx';

const me_get = defineEventHandler(async (event) => {
  try {
    if (event.method !== "GET") {
      throw createError({
        statusCode: 405,
        statusMessage: "Method Not Allowed"
      });
    }
    const token = getCookie(event, "auth-token");
    if (!token) {
      throw createError({
        statusCode: 401,
        statusMessage: "No authentication token found"
      });
    }
    const config = useRuntimeConfig();
    const secret = new TextEncoder().encode(config.jwtSecret);
    const { payload } = await jose.jwtVerify(token, secret);
    const decoded = payload;
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: {
        id: true,
        name: true,
        email: true,
        createdAt: true,
        updatedAt: true
      }
    });
    if (!user) {
      throw createError({
        statusCode: 401,
        statusMessage: "User not found"
      });
    }
    return {
      success: true,
      user
    };
  } catch (error) {
    console.error("Get user error:", error);
    if (error instanceof jose.errors.JWTExpired || error instanceof jose.errors.JWTInvalid || error instanceof jose.errors.JWSInvalid || error instanceof jose.errors.JWTClaimValidationFailed) {
      setCookie(event, "auth-token", "", {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 0
      });
      throw createError({
        statusCode: 401,
        statusMessage: "Invalid or expired token"
      });
    }
    if (error.statusCode) {
      throw error;
    }
    throw createError({
      statusCode: 500,
      statusMessage: "Internal server error"
    });
  } finally {
    await prisma.$disconnect();
  }
});

export { me_get as default };
//# sourceMappingURL=me.get.mjs.map
