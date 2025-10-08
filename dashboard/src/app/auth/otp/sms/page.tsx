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
import { InputOTP, InputOTPGroup, InputOTPSlot } from '@/components/ui/input-otp';
import { Spinner } from '@/components/ui/spinner';
import { ArrowLeft, Phone } from 'lucide-react';

const phoneSchema = z.object({
    phone: z.string().min(10, 'Please enter a valid phone number'),
});

const otpSchema = z.object({
    otp: z.string().length(6, 'OTP must be 6 digits'),
});

type PhoneForm = z.infer<typeof phoneSchema>;
type OTPForm = z.infer<typeof otpSchema>;

export default function SMSOTPPage() {
    const [step, setStep] = useState<'phone' | 'otp'>('phone');
    const [phone, setPhone] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [otpSent, setOtpSent] = useState(false);
    const { sendOTP, loginWithOTP, error, clearError } = useAuth();
    const router = useRouter();

    const phoneForm = useForm<PhoneForm>({
        resolver: zodResolver(phoneSchema),
    });

    const otpForm = useForm<OTPForm>({
        resolver: zodResolver(otpSchema),
    });

    const onSendOTP = async (data: PhoneForm) => {
        try {
            setIsLoading(true);
            clearError();
            await sendOTP(data.phone, 'sms', 'login');
            setPhone(data.phone);
            setStep('otp');
            setOtpSent(true);
        } catch (err) {
            // Error is handled by the auth context
        } finally {
            setIsLoading(false);
        }
    };

    const onVerifyOTP = async (data: OTPForm) => {
        try {
            setIsLoading(true);
            clearError();
            await loginWithOTP(phone, data.otp, 'sms');
            router.push('/dashboard');
        } catch (err) {
            // Error is handled by the auth context
        } finally {
            setIsLoading(false);
        }
    };

    const handleResendOTP = async () => {
        try {
            setIsLoading(true);
            clearError();
            await sendOTP(phone, 'sms', 'login');
            setOtpSent(true);
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
                        <div className="flex items-center space-x-2">
                            {step === 'otp' && (
                                <Button
                                    variant="ghost"
                                    size="icon"
                                    onClick={() => setStep('phone')}
                                    disabled={isLoading}
                                >
                                    <ArrowLeft className="h-4 w-4" />
                                </Button>
                            )}
                            <div className="flex-1">
                                <CardTitle className="text-2xl font-bold text-center">
                                    <Phone className="mx-auto mb-2 h-8 w-8" />
                                    SMS OTP
                                </CardTitle>
                                <CardDescription className="text-center">
                                    {step === 'phone'
                                        ? 'Enter your phone number to receive an OTP'
                                        : 'Enter the 6-digit code sent to your phone'}
                                </CardDescription>
                            </div>
                        </div>
                    </CardHeader>
                    <CardContent>
                        {step === 'phone' ? (
                            <form onSubmit={phoneForm.handleSubmit(onSendOTP)} className="space-y-4">
                                {error && (
                                    <Alert variant="destructive">
                                        <AlertDescription>{error}</AlertDescription>
                                    </Alert>
                                )}

                                <div className="space-y-2">
                                    <Label htmlFor="phone">Phone Number</Label>
                                    <Input
                                        id="phone"
                                        type="tel"
                                        placeholder="Enter your phone number"
                                        {...phoneForm.register('phone')}
                                        disabled={isLoading}
                                    />
                                    {phoneForm.formState.errors.phone && (
                                        <p className="text-sm text-destructive">
                                            {phoneForm.formState.errors.phone.message}
                                        </p>
                                    )}
                                </div>

                                <Button type="submit" className="w-full" disabled={isLoading}>
                                    {isLoading && <Spinner className="mr-2 h-4 w-4" />}
                                    Send OTP
                                </Button>
                            </form>
                        ) : (
                            <form onSubmit={otpForm.handleSubmit(onVerifyOTP)} className="space-y-4">
                                {error && (
                                    <Alert variant="destructive">
                                        <AlertDescription>{error}</AlertDescription>
                                    </Alert>
                                )}

                                {otpSent && (
                                    <Alert>
                                        <AlertDescription>
                                            OTP sent to {phone}. Please check your messages.
                                        </AlertDescription>
                                    </Alert>
                                )}

                                <div className="space-y-2">
                                    <Label htmlFor="otp">Enter OTP</Label>
                                    <div className="flex justify-center">
                                        <InputOTP
                                            maxLength={6}
                                            value={otpForm.watch('otp') || ''}
                                            onChange={(value) => otpForm.setValue('otp', value)}
                                            disabled={isLoading}
                                        >
                                            <InputOTPGroup>
                                                <InputOTPSlot index={0} />
                                                <InputOTPSlot index={1} />
                                                <InputOTPSlot index={2} />
                                                <InputOTPSlot index={3} />
                                                <InputOTPSlot index={4} />
                                                <InputOTPSlot index={5} />
                                            </InputOTPGroup>
                                        </InputOTP>
                                    </div>
                                    {otpForm.formState.errors.otp && (
                                        <p className="text-sm text-destructive text-center">
                                            {otpForm.formState.errors.otp.message}
                                        </p>
                                    )}
                                </div>

                                <Button type="submit" className="w-full" disabled={isLoading}>
                                    {isLoading && <Spinner className="mr-2 h-4 w-4" />}
                                    Verify OTP
                                </Button>

                                <div className="text-center">
                                    <Button
                                        type="button"
                                        variant="link"
                                        onClick={handleResendOTP}
                                        disabled={isLoading}
                                        className="text-sm"
                                    >
                                        Didn't receive the code? Resend OTP
                                    </Button>
                                </div>
                            </form>
                        )}

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