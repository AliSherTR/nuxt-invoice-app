import { d as defineEventHandler, c as createError, s as setCookie } from '../../../nitro/nitro.mjs';
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
import 'jose';
import 'node:url';
import 'ipx';

const logout_post = defineEventHandler(async (event) => {
  try {
    if (event.method !== "POST") {
      throw createError({
        statusCode: 405,
        statusMessage: "Method Not Allowed"
      });
    }
    setCookie(event, "auth-token", "", {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 0
      // Expire immediately
    });
    return {
      success: true,
      message: "Logout successful"
    };
  } catch (error) {
    console.error("Logout error:", error);
    throw createError({
      statusCode: 500,
      statusMessage: "Internal server error"
    });
  }
});

export { logout_post as default };
//# sourceMappingURL=logout.post.mjs.map
