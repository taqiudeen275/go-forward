'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { AuthGuard } from '@/components/auth/auth-guard';
import { DashboardLayout } from '@/components/layout/dashboard-layout';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Spinner } from '@/components/ui/spinner';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, databaseClient, DatabaseError } from '@/lib/database';
import { Database, Plus, Search, Eye, Edit, Trash2 } from 'lucide-react';

export default function DatabasePage() {
    const [tables, setTables] = useState<Table[]>([]);
    const [schemas, setSchemas] = useState<string[]>(['public']);
    const [selectedSchema, setSelectedSchema] = useState('public');
    const [searchTerm, setSearchTerm] = useState('');
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const loadTables = async (schema: string) => {
        try {
            setLoading(true);
            setError(null);
            const [tablesData, schemasData] = await Promise.all([
                databaseClient.getTables(schema),
                databaseClient.getSchemas(),
            ]);
            setTables(tablesData);
            setSchemas(schemasData);
        } catch (err) {
            if (err instanceof DatabaseError) {
                setError(err.message);
            } else {
                setError('Failed to load tables');
            }
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        loadTables(selectedSchema);
    }, [selectedSchema]);

    const handleDeleteTable = async (tableName: string) => {
        if (!confirm(`Are you sure you want to delete table "${tableName}"? This action cannot be undone.`)) {
            return;
        }

        try {
            await databaseClient.deleteTable(tableName, selectedSchema);
            await loadTables(selectedSchema);
        } catch (err) {
            if (err instanceof DatabaseError) {
                setError(err.message);
            } else {
                setError('Failed to delete table');
            }
        }
    };

    const filteredTables = tables.filter(table =>
        table.name.toLowerCase().includes(searchTerm.toLowerCase())
    );

    return (
        <AuthGuard>
            <DashboardLayout>
                <div className="space-y-6">
                    <div className="flex items-center justify-between">
                        <div>
                            <h1 className="text-3xl font-bold flex items-center">
                                <Database className="mr-3 h-8 w-8" />
                                Database Tables
                            </h1>
                            <p className="text-muted-foreground">
                                Manage your database tables and schema
                            </p>
                        </div>
                        <Button asChild>
                            <Link href="/dashboard/database/create">
                                <Plus className="mr-2 h-4 w-4" />
                                Create Table
                            </Link>
                        </Button>
                    </div>

                    {error && (
                        <Alert variant="destructive">
                            <AlertDescription>{error}</AlertDescription>
                        </Alert>
                    )}

                    <div className="flex items-center space-x-4">
                        <div className="flex-1 relative">
                            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                            <Input
                                placeholder="Search tables..."
                                value={searchTerm}
                                onChange={(e) => setSearchTerm(e.target.value)}
                                className="pl-10"
                            />
                        </div>
                        <Select value={selectedSchema} onValueChange={setSelectedSchema}>
                            <SelectTrigger className="w-48">
                                <SelectValue placeholder="Select schema" />
                            </SelectTrigger>
                            <SelectContent>
                                {schemas.map((schema) => (
                                    <SelectItem key={schema} value={schema}>
                                        {schema}
                                    </SelectItem>
                                ))}
                            </SelectContent>
                        </Select>
                    </div>

                    {loading ? (
                        <div className="flex items-center justify-center py-12">
                            <Spinner className="h-8 w-8" />
                        </div>
                    ) : filteredTables.length === 0 ? (
                        <Card>
                            <CardContent className="flex flex-col items-center justify-center py-12">
                                <Database className="h-12 w-12 text-muted-foreground mb-4" />
                                <h3 className="text-lg font-semibold mb-2">No tables found</h3>
                                <p className="text-muted-foreground text-center mb-4">
                                    {searchTerm
                                        ? `No tables match "${searchTerm}" in schema "${selectedSchema}"`
                                        : `No tables exist in schema "${selectedSchema}"`}
                                </p>
                                <Button asChild>
                                    <Link href="/dashboard/database/create">
                                        <Plus className="mr-2 h-4 w-4" />
                                        Create Your First Table
                                    </Link>
                                </Button>
                            </CardContent>
                        </Card>
                    ) : (
                        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                            {filteredTables.map((table) => (
                                <Card key={table.name} className="hover:shadow-md transition-shadow">
                                    <CardHeader>
                                        <div className="flex items-center justify-between">
                                            <CardTitle className="text-lg">{table.name}</CardTitle>
                                            <div className="flex items-center space-x-1">
                                                {table.rls_enabled && (
                                                    <Badge variant="secondary" className="text-xs">
                                                        RLS
                                                    </Badge>
                                                )}
                                                <Badge variant="outline" className="text-xs">
                                                    {table.schema}
                                                </Badge>
                                            </div>
                                        </div>
                                        <CardDescription>
                                            {table.columns.length} columns

                                        </CardDescription>
                                    </CardHeader>
                                    <CardContent>
                                        <div className="space-y-3">
                                            <div>
                                                <h4 className="text-sm font-medium mb-2">Columns</h4>
                                                <div className="space-y-1">
                                                    {table.columns.slice(0, 3).map((column) => (
                                                        <div key={column.name} className="flex items-center justify-between text-sm">
                                                            <span className="font-mono">{column.name}</span>
                                                            <div className="flex items-center space-x-1">
                                                                <Badge variant="outline" className="text-xs">
                                                                    {column.type}
                                                                </Badge>
                                                                {column.is_primary_key && (
                                                                    <Badge variant="default" className="text-xs">
                                                                        PK
                                                                    </Badge>
                                                                )}
                                                            </div>
                                                        </div>
                                                    ))}
                                                    {table.columns.length > 3 && (
                                                        <div className="text-xs text-muted-foreground">
                                                            +{table.columns.length - 3} more columns
                                                        </div>
                                                    )}
                                                </div>
                                            </div>

                                            <div className="flex items-center space-x-2 pt-2">
                                                <Button asChild size="sm" variant="outline" className="flex-1">
                                                    <Link href={`/dashboard/database/${table.schema}/${table.name}`}>
                                                        <Eye className="mr-1 h-3 w-3" />
                                                        View
                                                    </Link>
                                                </Button>
                                                <Button asChild size="sm" variant="outline" className="flex-1">
                                                    <Link href={`/dashboard/database/${table.schema}/${table.name}/edit`}>
                                                        <Edit className="mr-1 h-3 w-3" />
                                                        Edit
                                                    </Link>
                                                </Button>
                                                <Button
                                                    size="sm"
                                                    variant="outline"
                                                    onClick={() => handleDeleteTable(table.name)}
                                                    className="text-destructive hover:text-destructive"
                                                >
                                                    <Trash2 className="h-3 w-3" />
                                                </Button>
                                            </div>
                                        </div>
                                    </CardContent>
                                </Card>
                            ))}
                        </div>
                    )}
                </div>
            </DashboardLayout>
        </AuthGuard>
    );
}