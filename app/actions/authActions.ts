"use server";
import { PrismaClient, Prisma } from '@prisma/client';  

import { signIn, signOut } from "@/auth";
import { signUpSchema } from "@/lib/zod";
import { AuthError } from "next-auth";
import { getSessionTokenForTest } from "@/tests/utils/auth";
import { JWT } from "next-auth/jwt";

import bcryptjs from "bcryptjs";
const prisma = new PrismaClient({ log: ['query', 'info', 'warn', 'error'] });


export async function handleCredentialsSignin({ email, password }: {
    email: string,
    password: string
}) {
    try {
        await signIn("credentials", { email, password, redirectTo: "/" });
    } catch (error) {
        if (error instanceof AuthError) {
            switch (error.type) {
                case 'CredentialsSignin':
                    return {
                        message: 'Invalid credentials',
                    }
                default:
                    return {
                        message: 'Something went wrong.',
                    }
            }
        }
        throw error;
    }
}


export async function handleGithubSignin() {
    await signIn("github", { redirectTo: "/" });
}

export async function handleSignOut() {
    await signOut();
}
export async function handleSignUp({
    name,
    email,
    password,
    confirmPassword,
}: {
    name: string;
    email: string;
    password: string;
    confirmPassword: string;
}) {
    try {
        console.log("🔍 Received signup request:", { name, email, password, confirmPassword });

        // ✅ Validate input using Zod
        const parsedCredentials = signUpSchema.safeParse({ name, email, password, confirmPassword });
        if (!parsedCredentials.success) {
            console.error("❌ Validation failed:", parsedCredentials.error);
            return { success: false, message: "Invalid data." };
        }

        // ✅ Check if user already exists
        const existingUser = await prisma.user.findUnique({ where: { email } });
        if (existingUser) {
            console.warn("⚠️ Email already exists:", email);
            return { success: false, message: "Email already exists. Login to continue." };
        }

        // ✅ Hash the password
        const hashedPassword = await bcryptjs.hash(password, 10);
        console.log("🔐 Hashed password:", hashedPassword);

        // ✅ Create the user in the database
        console.log("🛠 Preparing to create user...");
        const newUser = await prisma.user.create({
            data: {
                name: name || "Unknown User",  // Ensure name is not null
                email,
                password: hashedPassword || null, // Allow nullable password
                role: "user",
            },
        });
        

        console.log("✅ User created successfully:", newUser);

        // ✅ Generate session token
        const sessionToken = await getSessionTokenForTest({
            id: newUser.id,
            email: newUser.email,
            role: newUser.role || "user",
        } as JWT);

        console.log("🔑 Generated session token:", sessionToken);

        return { success: true, message: "Account created successfully." };
    } catch (error: any) {
        console.error("🚨 Error in handleSignUp:", error);

        // ✅ Fix Prisma error handling
        if (error instanceof Prisma.PrismaClientKnownRequestError) {
            console.error("🔎 Prisma Error Code:", error.code);
        }

        return { success: false, message: "An unexpected error occurred. Please try again." };
    }
}