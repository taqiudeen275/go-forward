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

const loginSchema = z.object({
    identifier: z.string().min(1, 'Email, username, or phone is required'),
    password: z.string().min(1, 'Password is required'),
});

type LoginForm = z.infer<typeof loginSchema>;

export default function LoginPage() {
    const [isLoading, setIsLoading] = useState(false);
    const { login, error, clearError } = useAuth();
    const router = useRouter();

    const {
        register,
        handleSubmit,
        formState: { errors },
    } = useForm<LoginForm>({
        resolver: zodResolver(loginSchema),
    });

    const onSubmit = async (data: LoginForm) => {
        try {
            setIsLoading(true);
            clearError();
            await login(data.identifier, data.password);
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
                            Go Forward Admin
                        </CardTitle>
                        <CardDescription className="text-center">
                            Sign in to access the admin dashboard
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        <Tabs defaultValue="credentials" className="w-full">
                            <TabsList className="grid w-full grid-cols-2">
                                <TabsTrigger value="credentials">Credentials</TabsTrigger>
                                <TabsTrigger value="otp">OTP</TabsTrigger>
                            </TabsList>

                            <TabsContent value="credentials" className="space-y-4">
                                <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
                                    {error && (
                                        <Alert variant="destructive">
                                            <AlertDescription>{error}</AlertDescription>
                                        </Alert>
                                    )}

                                    <div className="space-y-2">
                                        <Label htmlFor="identifier">Email, Username, or Phone</Label>
                                        <Input
                                            id="identifier"
                                            type="text"
                                            placeholder="Enter your email, username, or phone"
                                            {...register('identifier')}
                                            disabled={isLoading}
                                        />
                                        {errors.identifier && (
                                            <p className="text-sm text-destructive">
                                                {errors.identifier.message}
                                            </p>
                                        )}
                                    </div>

                                    <div className="space-y-2">
                                        <Label htmlFor="password">Password</Label>
                                        <Input
                                            id="password"
                                            type="password"
                                            placeholder="Enter your password"
                                            {...register('password')}
                                            disabled={isLoading}
                                        />
                                        {errors.password && (
                                            <p className="text-sm text-destructive">
                                                {errors.password.message}
                                            </p>
                                        )}
                                    </div>

                                    <Button type="submit" className="w-full" disabled={isLoading}>
                                        {isLoading && <Spinner className="mr-2 h-4 w-4" />}
                                        Sign In
                                    </Button>
                                </form>

                                <div className="text-center text-sm">
                                    <Link
                                        href="/auth/forgot-password"
                                        className="text-primary hover:underline"
                                    >
                                        Forgot your password?
                                    </Link>
                                </div>
                            </TabsContent>

                            <TabsContent value="otp" className="space-y-4">
                                <div className="text-center">
                                    <p className="text-sm text-muted-foreground mb-4">
                                        Sign in using OTP sent to your email or phone
                                    </p>
                                    <div className="space-y-2">
                                        <Button asChild variant="outline" className="w-full">
                                            <Link href="/auth/otp/email">Sign in with Email OTP</Link>
                                        </Button>
                                        <Button asChild variant="outline" className="w-full">
                                            <Link href="/auth/otp/sms">Sign in with SMS OTP</Link>
                                        </Button>
                                    </div>
                                </div>
                            </TabsContent>
                        </Tabs>

                        <div className="mt-6 text-center text-sm">
                            <span className="text-muted-foreground">Don't have an account? </span>
                            <Link href="/auth/register" className="text-primary hover:underline">
                                Sign up
                            </Link>
                        </div>
                    </CardContent>
                </Card>
            </div>
        </AuthGuard>
    );
}