'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
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
import { KeyRound, CheckCircle } from 'lucide-react';

const resetPasswordSchema = z.object({
    newPassword: z.string().min(8, 'Password must be at least 8 characters'),
    confirmPassword: z.string(),
}).refine((data) => data.newPassword === data.confirmPassword, {
    message: "Passwords don't match",
    path: ["confirmPassword"],
});

type ResetPasswordForm = z.infer<typeof resetPasswordSchema>;

export default function ResetPasswordPage() {
    const [isLoading, setIsLoading] = useState(false);
    const [resetSuccess, setResetSuccess] = useState(false);
    const [token, setToken] = useState<string | null>(null);
    const { confirmResetPassword, error, clearError } = useAuth();
    const router = useRouter();
    const searchParams = useSearchParams();

    const {
        register,
        handleSubmit,
        formState: { errors },
    } = useForm<ResetPasswordForm>({
        resolver: zodResolver(resetPasswordSchema),
    });

    useEffect(() => {
        const tokenParam = searchParams.get('token');
        if (tokenParam) {
            setToken(tokenParam);
        } else {
            // Redirect to forgot password if no token
            router.push('/auth/forgot-password');
        }
    }, [searchParams, router]);

    const onSubmit = async (data: ResetPasswordForm) => {
        if (!token) return;

        try {
            setIsLoading(true);
            clearError();
            await confirmResetPassword(token, data.newPassword);
            setResetSuccess(true);
        } catch (err) {
            // Error is handled by the auth context
        } finally {
            setIsLoading(false);
        }
    };

    if (resetSuccess) {
        return (
            <AuthGuard requireAuth={false}>
                <div className="flex min-h-screen items-center justify-center bg-background px-4">
                    <Card className="w-full max-w-md">
                        <CardHeader className="space-y-1">
                            <CardTitle className="text-2xl font-bold text-center">
                                <CheckCircle className="mx-auto mb-2 h-8 w-8 text-green-600" />
                                Password Reset Successful
                            </CardTitle>
                            <CardDescription className="text-center">
                                Your password has been successfully reset
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <Alert>
                                <AlertDescription>
                                    Your password has been updated. You can now sign in with your new password.
                                </AlertDescription>
                            </Alert>

                            <Button asChild className="w-full">
                                <Link href="/auth/login">Sign In</Link>
                            </Button>
                        </CardContent>
                    </Card>
                </div>
            </AuthGuard>
        );
    }

    if (!token) {
        return (
            <div className="flex h-screen items-center justify-center">
                <Spinner className="h-8 w-8" />
            </div>
        );
    }

    return (
        <AuthGuard requireAuth={false}>
            <div className="flex min-h-screen items-center justify-center bg-background px-4">
                <Card className="w-full max-w-md">
                    <CardHeader className="space-y-1">
                        <CardTitle className="text-2xl font-bold text-center">
                            <KeyRound className="mx-auto mb-2 h-8 w-8" />
                            Set New Password
                        </CardTitle>
                        <CardDescription className="text-center">
                            Enter your new password below
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
                                <Label htmlFor="newPassword">New Password</Label>
                                <Input
                                    id="newPassword"
                                    type="password"
                                    placeholder="Enter your new password"
                                    {...register('newPassword')}
                                    disabled={isLoading}
                                />
                                {errors.newPassword && (
                                    <p className="text-sm text-destructive">
                                        {errors.newPassword.message}
                                    </p>
                                )}
                            </div>

                            <div className="space-y-2">
                                <Label htmlFor="confirmPassword">Confirm New Password</Label>
                                <Input
                                    id="confirmPassword"
                                    type="password"
                                    placeholder="Confirm your new password"
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
                                Update Password
                            </Button>
                        </form>

                        <div className="mt-6 text-center text-sm">
                            <Link href="/auth/login" className="text-primary hover:underline">
                                Back to login
                            </Link>
                        </div>
                    </CardContent>
                </Card>
            </div>
        </AuthGuard>
    );
}