import { d as defineEventHandler, c as createError, r as readBody, p as prisma, u as useRuntimeConfig, s as setCookie } from '../../../nitro/nitro.mjs';
import bcrypt from 'bcryptjs';
import * as jose from 'jose';
import { z } from 'zod';
import { s as signupSchema } from '../../../_/index.mjs';
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

const register_post = defineEventHandler(async (event) => {
  try {
    if (event.method !== "POST") {
      throw createError({
        statusCode: 405,
        statusMessage: "Method Not Allowed"
      });
    }
    const body = await readBody(event);
    const validatedData = signupSchema.parse(body);
    const { name, email, password } = validatedData;
    const existingUser = await prisma.user.findUnique({
      where: { email }
    });
    if (existingUser) {
      throw createError({
        statusCode: 400,
        statusMessage: "User already exists with this email"
      });
    }
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const user = await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword
      },
      select: {
        id: true,
        name: true,
        email: true,
        createdAt: true
      }
    });
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
    return {
      success: true,
      message: "User registered successfully",
      user
    };
  } catch (error) {
    console.error("Registration error:", error);
    if (error instanceof z.ZodError) {
      throw createError({
        statusCode: 400,
        statusMessage: "Validation failed",
        data: error.errors
      });
    }
    if (error.code === "P2002") {
      throw createError({
        statusCode: 400,
        statusMessage: "User already exists"
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

export { register_post as default };
//# sourceMappingURL=register.post.mjs.map
