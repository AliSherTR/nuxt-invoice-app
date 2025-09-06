import jwt from "jsonwebtoken";

const protectedRoutes = ["/dashboard", "/profile", "/invoices", "/settings"];
const guestOnlyRoutes = ["/login", "/signup"];

export default defineEventHandler(async (event) => {
  const url = event.node.req.url || "";

  if (
    url.startsWith("/api") ||
    url.startsWith("/_nuxt") ||
    url.startsWith("/favicon")
  ) {
    return;
  }

  const token = getCookie(event, "auth-token");
  let isAuthenticated = false;

  // Check if user has valid token
  if (token) {
    try {
      const config = useRuntimeConfig();
      jwt.verify(token, config.jwtSecret);
      isAuthenticated = true;
    } catch (error) {
      // Invalid token, clear it
      setCookie(event, "auth-token", "", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 0,
      });
      isAuthenticated = false;
    }
  }

  // Check protected routes
  const isProtectedRoute = protectedRoutes.some((route) =>
    url.startsWith(route)
  );
  if (isProtectedRoute && !isAuthenticated) {
    await sendRedirect(event, "/login");
    return;
  }

  // Check guest-only routes (redirect authenticated users away from login/signup)
  const isGuestOnlyRoute = guestOnlyRoutes.some((route) =>
    url.startsWith(route)
  );
  if (isGuestOnlyRoute && isAuthenticated) {
    await sendRedirect(event, "/dashboard");
    return;
  }
});
