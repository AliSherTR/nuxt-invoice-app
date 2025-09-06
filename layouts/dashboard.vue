<script setup lang="ts">
import { Moon, Sun } from "lucide-vue-next";
import logo from "../../public/logo.svg";
import avatar from "../../public/avatar.jpg";
import { useAuth } from "~/composables/useAuth";

const colorMode = useColorMode();
const switchColorMode = (color: string) => {
  colorMode.preference = color;
};

const { user, isLoading, fetchUser, logout } = useAuth();

onMounted(async () => {
  try {
    if (user.value) {
      return;
    }
    const fetchedUser = await fetchUser();

    if (!fetchedUser) {
      await navigateTo("/login");
    }
  } catch (error) {
    console.error("Failed to fetch user:", error);
    await navigateTo("/login");
  }
});
</script>
<template>
  <div>
    <!-- Loading State -->
    <div
      v-if="isLoading"
      class="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-[#0c0e16]"
    >
      <div class="text-center">
        <div
          class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600 mx-auto mb-4"
        ></div>
        <p class="text-gray-600 dark:text-gray-300">Loading...</p>
      </div>
    </div>

    <!-- Dashboard Layout (only show when user is loaded) -->
    <div v-else-if="user" class="flex h-screen overflow-hidden">
      <aside
        class="w-[7%] bg-[#373b53] h-full overflow-hidden rounded-r-4xl flex flex-col"
      >
        <div>
          <NuxtImg :src="logo" alt="" class="w-full" />
        </div>
        <div class="mt-auto mb-10">
          <div class="flex items-center justify-center">
            <ClientOnly>
              <div
                v-if="colorMode.preference === 'dark'"
                @click="switchColorMode('light')"
                class="cursor-pointer p-2"
              >
                <Sun color="white" />
              </div>
              <div
                v-else
                @click="switchColorMode('dark')"
                class="cursor-pointer p-2"
              >
                <Moon color="white" />
              </div>
            </ClientOnly>
          </div>
        </div>
        <hr class="dark:border-white border-gray-600" />
        <div class="flex items-center justify-center py-8">
          <img
            @click="logout"
            :src="avatar"
            alt="Avatar"
            class="size-12 rounded-full object-cover"
          />
        </div>
      </aside>
      <main
        class="flex-1 overflow-y-auto p-5 dark:bg-[#0c0e16] bg-white pt-12 w-full mx-auto flex items-center justify-center"
      >
        <div class="flex-1 max-w-xl">
          <slot />
          <Toaster />
        </div>
      </main>
    </div>
  </div>
</template>
