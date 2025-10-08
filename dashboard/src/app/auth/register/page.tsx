'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useAuth } from '@/components/providers/auth-provider';
import { AuthGuard } from '@/components/auth/auth-guard';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Spinner } from '@/components/ui/spinner';

const registerSchema = z.object({
    email: z.string().email('Please enter a valid email').optional().or(z.literal('')),
    phone: z.string().optional().or(z.literal('')),
    username: z.string().optional().or(z.literal('')),
    password: z.string().min(8, 'Password must be at least 8 characters'),
    confirmPassword: z.string(),
}).refine((data) => data.password === data.confirmPassword, {
    message: "Passwords don't match",
    path: ["confirmPassword"],
}).refine((data) => data.email || data.phone || data.username, {
    message: "Please provide at least one: email, phone, or username",
    path: ["email"],
});

type RegisterForm = z.infer<typeof registerSchema>;

export default function RegisterPage() {
    const [isLoading, setIsLoading] = useState(false);
    const [activeTab, setActiveTab] = useState('email');
    const { register: registerUser, error, clearError } = useAuth();
    const router = useRouter();

    const {
        register,
        handleSubmit,
        formState: { errors },
        watch,
    } = useForm<RegisterForm>({
        resolver: zodResolver(registerSchema),
    });

    const onSubmit = async (data: RegisterForm) => {
        try {
            setIsLoading(true);
            clearError();

            const { confirmPassword, ...registerData } = data;
            await registerUser(
                registerData.email || undefined,
                registerData.phone || undefined,
                registerData.username || undefined,
                registerData.password
            );

            router.push('/dashboard');
        } catch (err) {
            // Error is handled by the auth context
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <AuthGuard requireAuth={false}>
            <div className="flex min-h-screen items-center justify-center bg-background px-4">
                <Card className="w-full max-w-md">
                    <CardHeader className="space-y-1">
                        <CardTitle className="text-2xl font-bold text-center">
                            Create Account
                        </CardTitle>
                        <CardDescription className="text-center">
                            Sign up for Go Forward Admin access
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
                            {error && (
                                <Alert variant="destructive">
                                    <AlertDescription>{error}</AlertDescription>
                                </Alert>
                            )}

                            <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
                                <TabsList className="grid w-full grid-cols-3">
                                    <TabsTrigger value="email">Email</TabsTrigger>
                                    <TabsTrigger value="phone">Phone</TabsTrigger>
                                    <TabsTrigger value="username">Username</TabsTrigger>
                                </TabsList>

                                <TabsContent value="email" className="space-y-4">
                                    <div className="space-y-2">
                                        <Label htmlFor="email">Email Address</Label>
                                        <Input
                                            id="email"
                                            type="email"
                                            placeholder="Enter your email address"
                                            {...register('email')}
                                            disabled={isLoading}
                                        />
                                        {errors.email && (
                                            <p className="text-sm text-destructive">
                                                {errors.email.message}
                                            </p>
                                        )}
                                    </div>
                                </TabsContent>

                                <TabsContent value="phone" className="space-y-4">
                                    <div className="space-y-2">
                                        <Label htmlFor="phone">Phone Number</Label>
                                        <Input
                                            id="phone"
                                            type="tel"
                                            placeholder="Enter your phone number"
                                            {...register('phone')}
                                            disabled={isLoading}
                                        />
                                        {errors.phone && (
                                            <p className="text-sm text-destructive">
                                                {errors.phone.message}
                                            </p>
                                        )}
                                    </div>
                                </TabsContent>

                                <TabsContent value="username" className="space-y-4">
                                    <div className="space-y-2">
                                        <Label htmlFor="username">Username</Label>
                                        <Input
                                            id="username"
                                            type="text"
                                            placeholder="Choose a username"
                                            {...register('username')}
                                            disabled={isLoading}
                                        />
                                        {errors.username && (
                                            <p className="text-sm text-destructive">
                                                {errors.username.message}
                                            </p>
                                        )}
                                    </div>
                                </TabsContent>
                            </Tabs>

                            <div className="space-y-2">
                                <Label htmlFor="password">Password</Label>
                                <Input
                                    id="password"
                                    type="password"
                                    placeholder="Create a password"
                                    {...register('password')}
                                    disabled={isLoading}
                                />
                                {errors.password && (
                                    <p className="text-sm text-destructive">
                                        {errors.password.message}
                                    </p>
                                )}
                            </div>

                            <div className="space-y-2">
                                <Label htmlFor="confirmPassword">Confirm Password</Label>
                                <Input
                                    id="confirmPassword"
                                    type="password"
                                    placeholder="Confirm your password"
                                    {...register('confirmPassword')}
                                    disabled={isLoading}
                                />
                                {errors.confirmPassword && (
                                    <p className="text-sm text-destructive">
                                        {errors.confirmPassword.message}
                                    </p>
                                )}
                            </div>

                            <Button type="submit" className="w-full" disabled={isLoading}>
                                {isLoading && <Spinner className="mr-2 h-4 w-4" />}
                                Create Account
                            </Button>
                        </form>

                        <div className="mt-6 text-center text-sm">
                            <span className="text-muted-foreground">Already have an account? </span>
                            <Link href="/auth/login" className="text-primary hover:underline">
                                Sign in
                            </Link>
                        </div>
                    </CardContent>
                </Card>
            </div>
        </AuthGuard>
    );
}