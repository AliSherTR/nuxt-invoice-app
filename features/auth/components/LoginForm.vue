<script setup lang="ts">
import { toTypedSchema } from "@vee-validate/zod";
import { Eye, EyeOff } from "lucide-vue-next";
import { useForm } from "vee-validate";
import { ref } from "vue";
import {
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Button } from "~/components/ui/button";
import { loginSchema } from "../schema";
import { Input } from "~/components/ui/input";

const formSchema = toTypedSchema(loginSchema);
const form = useForm({
  validationSchema: formSchema,
});
const isPasswordVisible = ref(false);

const togglePassword = () => {
  isPasswordVisible.value = !isPasswordVisible.value;
};

const onSubmit = form.handleSubmit(async (values) => {
  await useFetch("/server/api/auth/login", {
    method: "POST",
    body: values,
  });
});
</script>

<template>
  <div>
    <div>
      <h1 class="text-2xl font-semibold mb-4">Invoicify</h1>
      <p class="text-sm dark:text-gray-300 text-black mb-6">
        Enter your credentials to sign in.
      </p>

      <form @submit="onSubmit" class="space-y-4">
        <FormField v-slot="{ componentField }" name="email">
          <FormItem>
            <FormLabel>Email</FormLabel>
            <FormControl>
              <Input
                type="Email"
                placeholder="johnDoe@example.com"
                v-bind="componentField"
              />
            </FormControl>
            <FormDescription></FormDescription>
            <FormMessage />
          </FormItem>
        </FormField>

        <FormField v-slot="{ componentField }" name="password">
          <FormItem>
            <FormLabel>Password</FormLabel>
            <FormControl>
              <div class="relative">
                <Input
                  :type="isPasswordVisible ? 'text' : 'password'"
                  placeholder="Enter Your password"
                  v-bind="componentField"
                />
                <button
                  @click="togglePassword"
                  @click.prevent
                  class="absolute inset-y-0 right-0 pr-3 flex items-center text-sm text-gray-600"
                >
                  <div v-if="isPasswordVisible"><EyeOff /></div>
                  <div v-else="isPasswordVisible"><Eye /></div>
                </button>
              </div>
            </FormControl>
            <FormDescription></FormDescription>
            <FormMessage />
          </FormItem>
        </FormField>

        <Button type="submit" class="w-full"> Login </Button>
      </form>

      <p class="mt-4 text-sm text-right">
        Don't Have an account?
        <NuxtLink to="/signup" class="underline text-indigo-600"
          >Register Now
        </NuxtLink>
      </p>
    </div>
  </div>
</template>
