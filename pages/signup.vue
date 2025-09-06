<script setup lang="ts">
import SignUpForm from "~/features/auth/components/SignUpForm.vue";

definePageMeta({
  layout: "auth",
});
useHead({
  title: "Invoicfiy | Sign Up",
});
</script>
<template>
  <SignUpForm />
</template>
