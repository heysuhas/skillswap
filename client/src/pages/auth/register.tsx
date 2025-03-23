import { useState } from "react";
import { useLocation } from "wouter";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useAuth } from "@/hooks/use-auth";
import { useToast } from "@/hooks/use-toast";
import { registerSchema } from "@shared/schema";

import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Loader2 } from "lucide-react";

export default function Register() {
  const [_, navigate] = useLocation();
  const { register } = useAuth();
  const { toast } = useToast();
  const [isLoading, setIsLoading] = useState(false);

  // Set up form validation with zod
  const form = useForm<z.infer<typeof registerSchema>>({
    resolver: zodResolver(registerSchema),
    defaultValues: {
      email: "",
      username: "",
      password: "",
    },
  });

  // Form submission handler
  async function onSubmit(values: z.infer<typeof registerSchema>) {
    setIsLoading(true);
    try {
      await register(values);
      navigate("/");
      toast({
        title: "Registration successful",
        description: "Welcome to SkillSwap!",
      });
    } catch (error: any) {
      toast({
        title: "Registration failed",
        description: error.message || "There was an error creating your account",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50 px-4">
      <Card className="w-full max-w-md">
        <CardHeader className="space-y-1">
          <div className="flex justify-center mb-4">
            <div className="flex items-center space-x-2">
              <svg className="w-8 h-8 text-primary-600" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M15 5L12 2M12 2L9 5M12 2V8M7.2 10.6C6.44699 10.6 5.82446 11.2225 5.82446 11.9755C5.82446 12.3397 5.99276 12.6711 6.25945 12.9041C6.56933 13.1755 7.00293 13.493 7.55631 13.9634C8.13122 14.455 8.49897 14.8939 8.75629 15.3398C8.99721 15.7596 9.12446 16.2274 9.12446 16.825C9.12446 18.3302 7.89966 19.5 6.42446 19.5C5.11928 19.5 3.99732 18.7073 3.67119 17.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                <path d="M16.8 10.6C17.553 10.6 18.1755 11.2225 18.1755 11.9755C18.1755 12.3397 18.0072 12.6711 17.7406 12.9041C17.4307 13.1755 16.9971 13.493 16.4437 13.9634C15.8688 14.455 15.501 14.8939 15.2437 15.3398C15.0028 15.7596 14.8755 16.2274 14.8755 16.825C14.8755 18.3302 16.1003 19.5 17.5755 19.5C18.8807 19.5 20.0027 18.7073 20.3288 17.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
              <h1 className="text-xl font-semibold text-primary-600">SkillSwap</h1>
            </div>
          </div>
          <CardTitle className="text-2xl text-center">Create an account</CardTitle>
          <CardDescription className="text-center">
            Register to start sharing and learning new skills
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              <FormField
                control={form.control}
                name="email"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Email</FormLabel>
                    <FormControl>
                      <Input 
                        placeholder="your.email@example.com" 
                        type="email"
                        autoComplete="email"
                        disabled={isLoading}
                        {...field}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="username"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Username</FormLabel>
                    <FormControl>
                      <Input 
                        placeholder="johndoe" 
                        autoComplete="username"
                        disabled={isLoading}
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
                    <FormLabel>Password</FormLabel>
                    <FormControl>
                      <Input 
                        placeholder="••••••••" 
                        type="password"
                        autoComplete="new-password"
                        disabled={isLoading}
                        {...field}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <Button type="submit" className="w-full" disabled={isLoading}>
                {isLoading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Creating account...
                  </>
                ) : (
                  "Register"
                )}
              </Button>
            </form>
          </Form>
        </CardContent>
        <CardFooter className="flex justify-center">
          <p className="text-sm text-slate-500">
            Already have an account?{" "}
            <Button variant="link" className="p-0 h-auto" onClick={() => navigate("/login")}>
              Log in
            </Button>
          </p>
        </CardFooter>
      </Card>
    </div>
  );
}
