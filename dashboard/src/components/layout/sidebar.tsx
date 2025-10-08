'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { cn } from '@/lib/utils';
import {
    Database,
    Users,
    Settings,
    FileText,
    Activity,
    Code,
    Home,
    LogOut,
} from 'lucide-react';
import { useAuth } from '@/components/providers/auth-provider';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';

const navigation = [
    { name: 'Dashboard', href: '/dashboard', icon: Home },
    { name: 'Database', href: '/dashboard/database', icon: Database },
    { name: 'SQL Editor', href: '/dashboard/sql', icon: Code },
    { name: 'Users', href: '/dashboard/users', icon: Users },
    { name: 'Storage', href: '/dashboard/storage', icon: FileText },
    { name: 'Logs', href: '/dashboard/logs', icon: Activity },
    { name: 'Settings', href: '/dashboard/settings', icon: Settings },
];

export function Sidebar() {
    const pathname = usePathname();
    const { logout, user } = useAuth();

    const handleLogout = async () => {
        try {
            await logout();
        } catch (error) {
            console.error('Logout failed:', error);
        }
    };

    return (
        <div className="flex h-full w-64 flex-col bg-card border-r">
            <div className="flex h-16 items-center px-6">
                <h1 className="text-xl font-semibold">Go Forward</h1>
            </div>

            <Separator />

            <nav className="flex-1 space-y-1 px-3 py-4">
                {navigation.map((item) => {
                    const isActive = pathname === item.href;
                    return (
                        <Link
                            key={item.name}
                            href={item.href}
                            className={cn(
                                'flex items-center rounded-md px-3 py-2 text-sm font-medium transition-colors',
                                isActive
                                    ? 'bg-primary text-primary-foreground'
                                    : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
                            )}
                        >
                            <item.icon className="mr-3 h-4 w-4" />
                            {item.name}
                        </Link>
                    );
                })}
            </nav>

            <Separator />

            <div className="p-4">
                <div className="mb-4 text-sm text-muted-foreground">
                    <div className="font-medium">{user?.username || user?.email || 'User'}</div>
                    <div className="text-xs">{user?.email}</div>
                </div>
                <Button
                    variant="outline"
                    size="sm"
                    onClick={handleLogout}
                    className="w-full justify-start"
                >
                    <LogOut className="mr-2 h-4 w-4" />
                    Logout
                </Button>
            </div>
        </div>
    );
}