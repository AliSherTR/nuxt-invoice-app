import bcrypt from "bcryptjs";
import * as jose from "jose";
import { z } from "zod";
import { signupSchema } from "~/features/auth/schema";
import { PrismaClient } from "~/lib/generated/prisma";
import prisma from "~/server/utils/prisma";

export default defineEventHandler(async (event) => {
  try {
    // Only allow POST requests
    if (event.method !== "POST") {
      throw createError({
        statusCode: 405,
        statusMessage: "Method Not Allowed",
      });
    }

    // Get request body
    const body = await readBody(event);

    // Validate input
    const validatedData = signupSchema.parse(body);
    const { name, email, password } = validatedData;

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      throw createError({
        statusCode: 400,
        statusMessage: "User already exists with this email",
      });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user
    const user = await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
      },
      select: {
        id: true,
        name: true,
        email: true,
        createdAt: true,
      },
    });

    // Generate JWT token using jose
    const config = useRuntimeConfig();
    const secret = new TextEncoder().encode(config.jwtSecret);

    const token = await new jose.SignJWT({
      userId: user.id,
      email: user.email,
    })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setExpirationTime("7d")
      .sign(secret);

    // Set HTTP-only cookie
    setCookie(event, "auth-token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 60 * 60 * 24 * 7, // 7 days
    });

    return {
      success: true,
      message: "User registered successfully",
      user,
    };
  } catch (error: any) {
    console.error("Registration error:", error);

    // Handle Zod validation errors
    if (error instanceof z.ZodError) {
      throw createError({
        statusCode: 400,
        statusMessage: "Validation failed",
        data: error.errors,
      });
    }

    // Handle Prisma errors
    if (error.code === "P2002") {
      throw createError({
        statusCode: 400,
        statusMessage: "User already exists",
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
