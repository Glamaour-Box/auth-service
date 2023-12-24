import { GLAMBOX_SERVICES } from 'src/types';
import { z } from 'zod';

const validationErrorMessages = {
  minPassword: 'Password must be at least 6 characters long',
  invalidPhone: 'Please enter a valid phone number',
};

export const signupSchema = z.object({
  name: z.string(),
  email: z.string().email(),
  password: z.string().min(6, { message: validationErrorMessages.minPassword }),
  phone: z.string().refine(
    (val) => {
      return /^(\+\d{1,4})?[-\s\d]{10}$/.test(val);
    },
    { message: validationErrorMessages.invalidPhone },
  ),
  service: z.enum([
    GLAMBOX_SERVICES.ECOMMERCE,
    GLAMBOX_SERVICES.FINTECH,
    GLAMBOX_SERVICES.LOGISTICS,
  ]),
});

export const signinSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6, { message: validationErrorMessages.minPassword }),
});
