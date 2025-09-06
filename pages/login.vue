<script setup lang="ts">
import LoginForm from "~/features/auth/components/LoginForm.vue";

definePageMeta({ layout: "auth" });
useHead({
  title: "Invoicify | Login",
});
</script>

<template>
  <LoginForm />
</template>
