<script setup lang="ts">
import { Eye, EyeOff } from "lucide-vue-next";
import { useForm } from "vee-validate";
import { ref } from "vue";
import {
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Button } from "~/components/ui/button";
import { SignUpFormSchema } from "../schema";
import { Input } from "~/components/ui/input";

const form = useForm({
  validationSchema: SignUpFormSchema,
});
const isPasswordVisible = ref(false);
const isConfirmPasswordVisible = ref(false);

const togglePassword = () => {
  isPasswordVisible.value = !isPasswordVisible.value;
};

const toggleConfirmPassword = () => {
  isConfirmPasswordVisible.value = !isConfirmPasswordVisible.value;
};

const onSubmit = form.handleSubmit(async (values) => {
  console.log(values);
});
</script>
<template>
  <div>
    <div>
      <h1 class="text-2xl font-semibold mb-4">Invoicify</h1>
      <p class="text-sm dark:text-gray-300 text-black mb-6">
        Enter your details to Sign Up.
      </p>

      <form @submit="onSubmit" class="space-y-4">
        <FormField v-slot="{ componentField }" name="name">
          <FormItem>
            <FormLabel>Name</FormLabel>
            <FormControl>
              <Input
                type="text"
                placeholder="John Doe"
                v-bind="componentField"
              />
            </FormControl>
            <FormMessage />
          </FormItem>
        </FormField>

        <FormField v-slot="{ componentField }" name="email">
          <FormItem>
            <FormLabel>Email</FormLabel>
            <FormControl>
              <Input
                type="email"
                placeholder="johnDoe@example.com"
                v-bind="componentField"
              />
            </FormControl>
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
                  @click.prevent="togglePassword"
                  class="absolute inset-y-0 right-0 pr-3 flex items-center text-sm text-gray-600"
                >
                  <div v-if="isPasswordVisible"><EyeOff /></div>
                  <div v-else><Eye /></div>
                </button>
              </div>
            </FormControl>
            <FormMessage />
          </FormItem>
        </FormField>

        <FormField v-slot="{ componentField }" name="confirm">
          <FormItem>
            <FormLabel>Confirm Password</FormLabel>
            <FormControl>
              <div class="relative">
                <Input
                  :type="isConfirmPasswordVisible ? 'text' : 'password'"
                  placeholder="Enter Your password"
                  v-bind="componentField"
                />
                <button
                  @click.prevent="toggleConfirmPassword"
                  class="absolute inset-y-0 right-0 pr-3 flex items-center text-sm text-gray-600 cursor-pointer"
                >
                  <div v-if="isConfirmPasswordVisible"><EyeOff /></div>
                  <div v-else><Eye /></div>
                </button>
              </div>
            </FormControl>
            <FormMessage />
          </FormItem>
        </FormField>

        <Button type="submit" class="w-full">Sign Up </Button>
      </form>

      <p class="mt-4 text-sm text-right">
        Already Have an account?
        <NuxtLink to="/login" class="underline text-indigo-600"
          >Login Now
        </NuxtLink>
      </p>
    </div>
  </div>
</template>
