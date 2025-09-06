<script setup lang="ts">
import { Moon, Sun } from "lucide-vue-next";
import logo from "../../public/logo.svg";

const colorMode = useColorMode();

const switchColorMode = (color: string) => {
  colorMode.preference = color;
};
</script>

<template>
  <div class="flex h-screen overflow-hidden">
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
</template>
