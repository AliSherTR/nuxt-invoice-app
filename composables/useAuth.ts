interface User {
  id: number;
  name: string;
  email: string;
  createdAt: string;
}

export const useAuth = () => {
  // Global auth state
  const user = useState<User | null>("auth.user", () => null);
  const isLoading = useState<boolean>("auth.loading", () => false);

  // Computed
  const isLoggedIn = computed(() => !!user.value);

  // Fetch user from backend (your separate API)
  const fetchUser = async (): Promise<User | null> => {
    try {
      isLoading.value = true;

      const response = await $fetch("/api/auth/me", {
        method: "GET",
      });

      if (response && response.user) {
        user.value = response.user;
        return response.user;
      } else {
        user.value = null;
        return null;
      }
    } catch (error) {
      console.error("Failed to fetch user:", error);
      user.value = null;
      return null;
    } finally {
      isLoading.value = false;
    }
  };

  // Login function
  const login = async (credentials: { email: string; password: string }) => {
    try {
      isLoading.value = true;

      const response = await $fetch("/api/auth/login", {
        method: "POST",
        body: credentials,
      });

      if (response && response.success && response.user) {
        user.value = response.user;
        console.log("Login Successful");

        await navigateTo("/dashboard");
        return { success: true };
      } else {
        return {
          success: false,
          message: response?.message || "Login failed",
        };
      }
    } catch (error: any) {
      console.error("Login error:", error);
      return {
        success: false,
        message: error.data?.message || error.message || "Login failed",
      };
    } finally {
      isLoading.value = false;
    }
  };

  // Register function
  const register = async (data: {
    name: string;
    email: string;
    password: string;
    confirm: string;
  }) => {
    try {
      isLoading.value = true;

      const response = await $fetch("/api/auth/register", {
        method: "POST",
        body: data,
      });

      if (response && response.success && response.user) {
        user.value = response.user;
        await navigateTo("/dashboard");
        return { success: true };
      } else {
        return {
          success: false,
          message: response?.message || "Registration failed",
        };
      }
    } catch (error: any) {
      console.error("Registration error:", error);
      return {
        success: false,
        message: error.data?.message || error.message || "Registration failed",
      };
    } finally {
      isLoading.value = false;
    }
  };

  // Logout function
  const logout = async () => {
    try {
      await $fetch("/api/auth/logout", {
        method: "POST",
      });
    } catch (error) {
      console.error("Logout error:", error);
      // Continue with logout even if API call fails
    } finally {
      // Clear user state and redirect
      user.value = null;
      await navigateTo("/login");
    }
  };

  // Initialize auth (check if user is already logged in)
  const initAuth = async () => {
    // If user is already loaded, skip
    if (user.value) return user.value;

    // Fetch user data
    return await fetchUser();
  };

  // Clear auth state
  const clearAuth = () => {
    user.value = null;
  };

  return {
    // State
    user: readonly(user),
    isLoading: readonly(isLoading),
    isLoggedIn,

    // Actions
    fetchUser,
    login,
    register,
    logout,
    initAuth,
    clearAuth,
  };
};
