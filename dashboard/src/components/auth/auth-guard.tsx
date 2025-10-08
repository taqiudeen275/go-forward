'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/components/providers/auth-provider';
import { Spinner } from '@/components/ui/spinner';

interface AuthGuardProps {
    children: React.ReactNode;
    requireAuth?: boolean;
}

export function AuthGuard({ children, requireAuth = true }: AuthGuardProps) {
    const { isAuthenticated, loading } = useAuth();
    const router = useRouter();

    useEffect(() => {
        if (!loading) {
            if (requireAuth && !isAuthenticated) {
                router.push('/auth/login');
            } else if (!requireAuth && isAuthenticated) {
                router.push('/dashboard');
            }
        }
    }, [isAuthenticated, loading, requireAuth, router]);

    if (loading) {
        return (
            <div className="flex h-screen items-center justify-center">
                <Spinner className="h-8 w-8" />
            </div>
        );
    }

    if (requireAuth && !isAuthenticated) {
        return null;
    }

    if (!requireAuth && isAuthenticated) {
        return null;
    }

    return <>{children}</>;
}