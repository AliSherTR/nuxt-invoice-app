import { e as useState, n as navigateTo } from './server.mjs';
import { computed, readonly } from 'vue';

const useAuth = () => {
  const user = useState("auth.user", () => null);
  const isLoading = useState("auth.loading", () => false);
  const isLoggedIn = computed(() => !!user.value);
  const fetchUser = async () => {
    try {
      isLoading.value = true;
      const response = await $fetch("/api/auth/me", {
        method: "GET"
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
  const login = async (credentials) => {
    var _a;
    try {
      isLoading.value = true;
      const response = await $fetch("/api/auth/login", {
        method: "POST",
        body: credentials
      });
      if (response && response.success && response.user) {
        user.value = response.user;
        console.log("Login Successful");
        await navigateTo("/dashboard");
        return { success: true };
      } else {
        return {
          success: false,
          message: (response == null ? void 0 : response.message) || "Login failed"
        };
      }
    } catch (error) {
      console.error("Login error:", error);
      return {
        success: false,
        message: ((_a = error.data) == null ? void 0 : _a.message) || error.message || "Login failed"
      };
    } finally {
      isLoading.value = false;
    }
  };
  const register = async (data) => {
    var _a;
    try {
      isLoading.value = true;
      const response = await $fetch("/api/auth/register", {
        method: "POST",
        body: data
      });
      if (response && response.success && response.user) {
        user.value = response.user;
        await navigateTo("/dashboard");
        return { success: true };
      } else {
        return {
          success: false,
          message: (response == null ? void 0 : response.message) || "Registration failed"
        };
      }
    } catch (error) {
      console.error("Registration error:", error);
      return {
        success: false,
        message: ((_a = error.data) == null ? void 0 : _a.message) || error.message || "Registration failed"
      };
    } finally {
      isLoading.value = false;
    }
  };
  const logout = async () => {
    try {
      await $fetch("/api/auth/logout", {
        method: "POST"
      });
    } catch (error) {
      console.error("Logout error:", error);
    } finally {
      user.value = null;
      await navigateTo("/login");
    }
  };
  const initAuth = async () => {
    if (user.value) return user.value;
    return await fetchUser();
  };
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
    clearAuth
  };
};

export { useAuth as u };
//# sourceMappingURL=useAuth-Bban5XjU.mjs.map
