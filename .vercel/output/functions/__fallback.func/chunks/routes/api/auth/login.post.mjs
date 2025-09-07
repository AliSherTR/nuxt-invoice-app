import { d as defineEventHandler, c as createError, r as readBody, p as prisma, u as useRuntimeConfig, s as setCookie } from '../../../nitro/nitro.mjs';
import bcrypt from 'bcryptjs';
import * as jose from 'jose';
import { z } from 'zod';
import { l as loginSchema } from '../../../_/index.mjs';
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
import '@vee-validate/zod';

const login_post = defineEventHandler(async (event) => {
  try {
    if (event.method !== "POST") {
      throw createError({
        statusCode: 405,
        statusMessage: "Method Not Allowed"
      });
    }
    const body = await readBody(event);
    const validatedData = loginSchema.parse(body);
    const { email, password } = validatedData;
    const user = await prisma.user.findUnique({
      where: { email }
    });
    if (!user) {
      throw createError({
        statusCode: 401,
        statusMessage: "Invalid credentials"
      });
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw createError({
        statusCode: 401,
        statusMessage: "Invalid credentials"
      });
    }
    const config = useRuntimeConfig();
    const secret = new TextEncoder().encode(config.jwtSecret);
    const token = await new jose.SignJWT({
      userId: user.id,
      email: user.email
    }).setProtectedHeader({ alg: "HS256" }).setIssuedAt().setExpirationTime("7d").sign(secret);
    setCookie(event, "auth-token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 60 * 60 * 24 * 7
      // 7 days
    });
    const { password: _, ...userWithoutPassword } = user;
    return {
      success: true,
      message: "Login successful",
      user: userWithoutPassword
    };
  } catch (error) {
    console.error("Login error:", error);
    if (error instanceof z.ZodError) {
      throw createError({
        statusCode: 400,
        statusMessage: "Validation failed",
        data: error.errors
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

export { login_post as default };
//# sourceMappingURL=login.post.mjs.map
