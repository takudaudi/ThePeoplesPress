"use server";

import { eq } from "drizzle-orm";
import { db } from "@/database/drizzle";
import { users } from "@/database/schema";
import { hash } from "bcryptjs";
import { signIn } from "@/auth";
import { headers } from "next/headers";
import ratelimit from "@/lib/ratelimit";
import { redirect } from "next/navigation";
import { workflowClient } from "@/lib/workflow";
import config from "@/lib/config";

export const signInWithCredentials = async (
  params: Pick<AuthCredentials, "email" | "password">,
) => {
  const { email, password } = params;

  const ip = (await headers()).get("x-forwarded-for") || "127.0.0.1";
  const { success } = await ratelimit.limit(ip);

  if (!success) return redirect("/too-fast");

  try {
    const result = await signIn("credentials", {
      email,
      password,
      redirect: false,
    });

    if (result?.error) {
      console.error(`SignIn error for ${email}: ${result.error}`);
      return { success: false, error: result.error };
    }

    return { success: true };
  } catch (error) {
    console.error("Signin error:", error);
    return { success: false, error: "An unexpected error occurred" };
  }
};

export const signUp = async (params: AuthCredentials) => {
  const { fullName, email, universityId, password, universityCard } = params;

  const ip = (await headers()).get("x-forwarded-for") || "127.0.0.1";
  const { success } = await ratelimit.limit(ip);

  if (!success) return redirect("/too-fast");

  const existingUser = await db
    .select()
    .from(users)
    .where(eq(users.email, email))
    .limit(1);

  if (existingUser.length > 0) {
    console.log(`User already exists: ${email}`);
    return { success: false, error: "User already exists" };
  }

  // Validate universityId and universityCard if necessary
  if (!universityId || !universityCard) {
    return { success: false, error: "University details are required" };
  }

  const hashedPassword = await hash(password, 10);

  try {
    await db.insert(users).values({
      fullName,
      email,
      universityId,
      password: hashedPassword,
      universityCard,
    });

    // Trigger onboarding workflow
    await workflowClient.trigger({
      url: `${config.env.apiEndpoint}/api/workflows/onboarding`,
      body: {
        email,
        fullName,
      },
    });

    // Log user in immediately after registration
    const signInResult = await signInWithCredentials({ email, password });
    if (!signInResult.success) {
      console.error(`Sign in failed after successful registration for ${email}`);
      return { success: false, error: "Sign-in failed after registration" };
    }

    return { success: true };
  } catch (error) {
    console.error("Signup error:", error);
    return { success: false, error: "An unexpected error occurred during signup" };
  }
};
