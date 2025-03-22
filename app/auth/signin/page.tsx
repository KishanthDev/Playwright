"use client";

import { Card, CardContent, CardHeader, CardTitle } from "../../../components/ui/card";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "../../../components/ui/form";
import { Input } from "../../../components/ui/input";

import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";

import { signInSchema } from "../../../lib/zod";
import LoadingButton from "../../../components/loading-button";
import { handleCredentialsSignin } from "../../../app/actions/authActions";
import { useState, Suspense } from "react"; // Add Suspense
import ErrorMessage from "../../../components/error-message";

import { useSearchParams } from "next/navigation";

// Wrap the component using useSearchParams() in Suspense
function SignInForm() {
  const params = useSearchParams();
  const error = params.get("error");

  const [globalError, setGlobalError] = useState<string>("");

  // Handle the error query parameter
  if (error) {
    switch (error) {
      case "OAuthAccountNotLinked":
        setGlobalError("Please use your email and password to sign in.");
        break;
      default:
        setGlobalError("An unexpected error occurred. Please try again.");
    }
  }

  const form = useForm<z.infer<typeof signInSchema>>({
    resolver: zodResolver(signInSchema),
    defaultValues: {
      email: "",
      password: "",
    },
  });

  const onSubmit = async (values: z.infer<typeof signInSchema>) => {
    try {
      const result = await handleCredentialsSignin(values);
      if (result?.message) {
        setGlobalError(result.message);
      }
    } catch (error) {
      console.log("An unexpected error occurred. Please try again.");
    }
  };

  return (
    <div className="grow flex items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="text-3xl font-bold text-center text-gray-800">
            Welcome Back
          </CardTitle>
        </CardHeader>
        <CardContent>
          {globalError && <ErrorMessage error={globalError} />}
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-8">
              <FormField
                control={form.control}
                name="email"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel htmlFor="email">Email</FormLabel>
                    <FormControl>
                      <Input
                        id="email"
                        type="email"
                        placeholder="Enter your email address"
                        autoComplete="off"
                        {...field}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="password"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel htmlFor="password">Password</FormLabel>
                    <FormControl>
                      <Input
                        id="password"
                        type="password"
                        placeholder="Enter password"
                        {...field}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <LoadingButton pending={form.formState.isSubmitting}>
                Sign in
              </LoadingButton>
            </form>
          </Form>
        </CardContent>
      </Card>
    </div>
  );
}

export default function SignIn() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <SignInForm />
    </Suspense>
  );
}