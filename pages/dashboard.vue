<script setup lang="ts">
import { toast } from "vue-sonner";
import { useAuth } from "~/composables/useAuth";

definePageMeta({
  layout: "dashboard",
});

const { user } = useAuth();
</script>

<template>
  <div>
    <h1 class="text-2xl font-bold text-gray-900 dark:text-white mb-6">
      Dashboard
    </h1>
    <Button
      variant="outline"
      @click="
        () => {
          toast('Event has been created', {
            description: 'Sunday, December 03, 2023 at 9:00 AM',
            action: {
              label: 'Undo',
              onClick: () => console.log('Undo'),
            },
          });
        }
      "
    >
      Add to calendar
    </Button>

    <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
      <h2 class="text-lg font-semibold mb-4 dark:text-white">
        Welcome back, {{ user?.name }}!
      </h2>

      <div class="space-y-2 text-sm text-gray-600 dark:text-gray-300">
        <p><span class="font-medium">Email:</span> {{ user?.email }}</p>
        <p><span class="font-medium">User ID:</span> {{ user?.id }}</p>
      </div>
    </div>

    <!-- Your dashboard content goes here -->
  </div>
</template>
