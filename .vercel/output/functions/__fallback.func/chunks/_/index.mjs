import { z } from 'zod';
import { toTypedSchema } from '@vee-validate/zod';

const loginSchema = z.object({
  email: z.string({
    required_error: "Email is required"
  }).email("Invalid email"),
  password: z.string({
    required_error: "Password is required"
  })
});
toTypedSchema(loginSchema);
const signupSchema = z.object({
  name: z.string({
    required_error: "Name is required"
  }).min(2, "Too short"),
  email: z.string({
    required_error: "Email is required"
  }).email("Invalid email"),
  password: z.string({
    required_error: "Password is required"
  }).min(6, "At least 6 characters"),
  confirm: z.string({
    required_error: "Please confirm your password"
  })
}).refine((d) => d.password === d.confirm, {
  message: "Passwords do not match",
  path: ["confirm"]
});
toTypedSchema(signupSchema);

export { loginSchema as l, signupSchema as s };
//# sourceMappingURL=index.mjs.map
