'use client';

import { useState } from 'react';
import Link from 'next/link';
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
import { Spinner } from '@/components/ui/spinner';
import { ArrowLeft, KeyRound } from 'lucide-react';

const forgotPasswordSchema = z.object({
    identifier: z.string().min(1, 'Email, username, or phone is required'),
});

type ForgotPasswordForm = z.infer<typeof forgotPasswordSchema>;

export default function ForgotPasswordPage() {
    const [isLoading, setIsLoading] = useState(false);
    const [emailSent, setEmailSent] = useState(false);
    const { resetPassword, error, clearError } = useAuth();

    const {
        register,
        handleSubmit,
        formState: { errors },
        getValues,
    } = useForm<ForgotPasswordForm>({
        resolver: zodResolver(forgotPasswordSchema),
    });

    const onSubmit = async (data: ForgotPasswordForm) => {
        try {
            setIsLoading(true);
            clearError();
            await resetPassword(data.identifier);
            setEmailSent(true);
        } catch (err) {
            // Error is handled by the auth context
        } finally {
            setIsLoading(false);
        }
    };

    if (emailSent) {
        return (
            <AuthGuard requireAuth={false}>
                <div className="flex min-h-screen items-center justify-center bg-background px-4">
                    <Card className="w-full max-w-md">
                        <CardHeader className="space-y-1">
                            <CardTitle className="text-2xl font-bold text-center">
                                <KeyRound className="mx-auto mb-2 h-8 w-8" />
                                Check Your Email
                            </CardTitle>
                            <CardDescription className="text-center">
                                Password reset instructions sent
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <Alert>
                                <AlertDescription>
                                    We've sent password reset instructions to {getValues('identifier')}.
                                    Please check your email and follow the link to reset your password.
                                </AlertDescription>
                            </Alert>

                            <div className="space-y-2">
                                <Button asChild className="w-full">
                                    <Link href="/auth/login">Back to Login</Link>
                                </Button>
                                <Button
                                    variant="outline"
                                    onClick={() => setEmailSent(false)}
                                    className="w-full"
                                >
                                    Try Different Email
                                </Button>
                            </div>
                        </CardContent>
                    </Card>
                </div>
            </AuthGuard>
        );
    }

    return (
        <AuthGuard requireAuth={false}>
            <div className="flex min-h-screen items-center justify-center bg-background px-4">
                <Card className="w-full max-w-md">
                    <CardHeader className="space-y-1">
                        <CardTitle className="text-2xl font-bold text-center">
                            <KeyRound className="mx-auto mb-2 h-8 w-8" />
                            Reset Password
                        </CardTitle>
                        <CardDescription className="text-center">
                            Enter your email, username, or phone to reset your password
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
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

                            <Button type="submit" className="w-full" disabled={isLoading}>
                                {isLoading && <Spinner className="mr-2 h-4 w-4" />}
                                Send Reset Instructions
                            </Button>
                        </form>

                        <div className="mt-6 text-center text-sm">
                            <Link
                                href="/auth/login"
                                className="inline-flex items-center text-primary hover:underline"
                            >
                                <ArrowLeft className="mr-1 h-4 w-4" />
                                Back to login
                            </Link>
                        </div>
                    </CardContent>
                </Card>
            </div>
        </AuthGuard>
    );
}