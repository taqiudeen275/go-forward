'use client';

import { AuthGuard } from '@/components/auth/auth-guard';
import { DashboardLayout } from '@/components/layout/dashboard-layout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Database, Users, FileText, Activity, Code, Server } from 'lucide-react';

const stats = [
    {
        title: 'Total Tables',
        value: '12',
        description: 'Database tables',
        icon: Database,
    },
    {
        title: 'Active Users',
        value: '24',
        description: 'Registered users',
        icon: Users,
    },
    {
        title: 'Storage Used',
        value: '2.4 GB',
        description: 'File storage',
        icon: FileText,
    },
    {
        title: 'API Requests',
        value: '1,234',
        description: 'Last 24 hours',
        icon: Activity,
    },
];

export default function DashboardPage() {
    return (
        <AuthGuard>
            <DashboardLayout>
                <div className="space-y-6">
                    <div>
                        <h1 className="text-3xl font-bold">Dashboard</h1>
                        <p className="text-muted-foreground">
                            Welcome to Go Forward Admin Dashboard
                        </p>
                    </div>

                    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                        {stats.map((stat) => (
                            <Card key={stat.title}>
                                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                                    <CardTitle className="text-sm font-medium">
                                        {stat.title}
                                    </CardTitle>
                                    <stat.icon className="h-4 w-4 text-muted-foreground" />
                                </CardHeader>
                                <CardContent>
                                    <div className="text-2xl font-bold">{stat.value}</div>
                                    <p className="text-xs text-muted-foreground">
                                        {stat.description}
                                    </p>
                                </CardContent>
                            </Card>
                        ))}
                    </div>

                    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                        <Card>
                            <CardHeader>
                                <CardTitle className="flex items-center">
                                    <Database className="mr-2 h-5 w-5" />
                                    Database Management
                                </CardTitle>
                                <CardDescription>
                                    Manage your database tables and schema
                                </CardDescription>
                            </CardHeader>
                            <CardContent>
                                <p className="text-sm text-muted-foreground">
                                    Create, modify, and manage database tables with our visual editor
                                    or SQL interface.
                                </p>
                            </CardContent>
                        </Card>

                        <Card>
                            <CardHeader>
                                <CardTitle className="flex items-center">
                                    <Code className="mr-2 h-5 w-5" />
                                    SQL Editor
                                </CardTitle>
                                <CardDescription>
                                    Execute SQL queries directly
                                </CardDescription>
                            </CardHeader>
                            <CardContent>
                                <p className="text-sm text-muted-foreground">
                                    Run custom SQL queries with syntax highlighting and result
                                    formatting.
                                </p>
                            </CardContent>
                        </Card>

                        <Card>
                            <CardHeader>
                                <CardTitle className="flex items-center">
                                    <Server className="mr-2 h-5 w-5" />
                                    API Services
                                </CardTitle>
                                <CardDescription>
                                    Auto-generated REST endpoints
                                </CardDescription>
                            </CardHeader>
                            <CardContent>
                                <p className="text-sm text-muted-foreground">
                                    Automatically generated CRUD APIs for all your database tables.
                                </p>
                            </CardContent>
                        </Card>
                    </div>
                </div>
            </DashboardLayout>
        </AuthGuard>
    );
}