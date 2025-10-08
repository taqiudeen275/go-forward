'use client';

import { useState } from 'react';
import { AuthGuard } from '@/components/auth/auth-guard';
import { DashboardLayout } from '@/components/layout/dashboard-layout';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Spinner } from '@/components/ui/spinner';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { QueryResult, databaseClient, DatabaseError } from '@/lib/database';
import '@/lib/debug-database'; // Add debug functions to window
import { DatabaseDebug } from '@/components/debug/database-debug';
import { Play, Download, Clock, Database, AlertCircle } from 'lucide-react';

export default function SQLEditorPage() {
    const [query, setQuery] = useState('SELECT * FROM users LIMIT 10;');
    const [result, setResult] = useState<QueryResult | null>(null);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [queryHistory, setQueryHistory] = useState<Array<{
        query: string;
        timestamp: Date;
        success: boolean;
        executionTime?: number;
    }>>([]);

    const executeQuery = async () => {
        if (!query.trim()) return;

        try {
            setIsLoading(true);
            setError(null);

            const startTime = Date.now();
            const queryResult = await databaseClient.executeSQL(query.trim());
            const endTime = Date.now();

            setResult(queryResult);
            setQueryHistory(prev => [{
                query: query.trim(),
                timestamp: new Date(),
                success: true,
                executionTime: endTime - startTime,
            }, ...prev.slice(0, 9)]); // Keep last 10 queries

        } catch (err) {
            if (err instanceof DatabaseError) {
                setError(err.message);
            } else {
                setError('Failed to execute query');
            }

            setQueryHistory(prev => [{
                query: query.trim(),
                timestamp: new Date(),
                success: false,
            }, ...prev.slice(0, 9)]);
        } finally {
            setIsLoading(false);
        }
    };

    const downloadResults = () => {
        if (!result) return;

        const csv = [
            result.columns.join(','),
            ...result.rows.map(row =>
                result.columns.map(col => {
                    const value = row[col];
                    if (value === null) return '';
                    if (typeof value === 'string' && value.includes(',')) {
                        return `"${value.replace(/"/g, '""')}"`;
                    }
                    return String(value);
                }).join(',')
            )
        ].join('\n');

        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'query_results.csv';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };

    const loadQueryFromHistory = (historicalQuery: string) => {
        setQuery(historicalQuery);
    };

    const commonQueries = [
        'SELECT * FROM users LIMIT 10;',
        'SHOW TABLES;',
        'SELECT table_name FROM information_schema.tables WHERE table_schema = \'public\';',
        'SELECT column_name, data_type FROM information_schema.columns WHERE table_name = \'users\';',
        'SELECT COUNT(*) FROM users;',
    ];

    return (
        <AuthGuard>
            <DashboardLayout>
                <div className="space-y-6">
                    <div>
                        <h1 className="text-3xl font-bold flex items-center">
                            <Database className="mr-3 h-8 w-8" />
                            SQL Editor
                        </h1>
                        <p className="text-muted-foreground">
                            Execute SQL queries directly against your database
                        </p>
                    </div>

                    {/* Debug component - remove this after testing */}
                    <DatabaseDebug />

                    <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
                        <div className="lg:col-span-3 space-y-6">
                            <Card>
                                <CardHeader>
                                    <div className="flex items-center justify-between">
                                        <div>
                                            <CardTitle>Query Editor</CardTitle>
                                            <CardDescription>
                                                Write and execute SQL queries
                                            </CardDescription>
                                        </div>
                                        <div className="flex items-center space-x-2">
                                            <Button
                                                onClick={executeQuery}
                                                disabled={isLoading || !query.trim()}
                                                size="sm"
                                            >
                                                {isLoading ? (
                                                    <Spinner className="mr-2 h-4 w-4" />
                                                ) : (
                                                    <Play className="mr-2 h-4 w-4" />
                                                )}
                                                Execute
                                            </Button>
                                            {result && (
                                                <Button
                                                    onClick={downloadResults}
                                                    variant="outline"
                                                    size="sm"
                                                >
                                                    <Download className="mr-2 h-4 w-4" />
                                                    Export CSV
                                                </Button>
                                            )}
                                        </div>
                                    </div>
                                </CardHeader>
                                <CardContent>
                                    <Textarea
                                        value={query}
                                        onChange={(e) => setQuery(e.target.value)}
                                        placeholder="Enter your SQL query here..."
                                        className="min-h-[200px] font-mono text-sm"
                                        disabled={isLoading}
                                    />
                                </CardContent>
                            </Card>

                            {error && (
                                <Alert variant="destructive">
                                    <AlertCircle className="h-4 w-4" />
                                    <AlertDescription>{error}</AlertDescription>
                                </Alert>
                            )}

                            {result && (
                                <Card>
                                    <CardHeader>
                                        <div className="flex items-center justify-between">
                                            <CardTitle>Query Results</CardTitle>
                                            <div className="flex items-center space-x-4 text-sm text-muted-foreground">
                                                <div className="flex items-center">
                                                    <Clock className="mr-1 h-4 w-4" />
                                                    {result.execution_time}
                                                </div>
                                                <Badge variant="outline">
                                                    {result.rows_affected || result.rows.length} rows
                                                </Badge>
                                            </div>
                                        </div>
                                    </CardHeader>
                                    <CardContent>
                                        {result.rows.length === 0 ? (
                                            <div className="text-center py-8 text-muted-foreground">
                                                Query executed successfully but returned no results.
                                            </div>
                                        ) : (
                                            <div className="overflow-auto max-h-96">
                                                <Table>
                                                    <TableHeader>
                                                        <TableRow>
                                                            {result.columns.map((column) => (
                                                                <TableHead key={column} className="font-mono text-xs">
                                                                    {column}
                                                                </TableHead>
                                                            ))}
                                                        </TableRow>
                                                    </TableHeader>
                                                    <TableBody>
                                                        {result.rows.map((row, index) => (
                                                            <TableRow key={index}>
                                                                {result.columns.map((column) => (
                                                                    <TableCell key={column} className="font-mono text-xs">
                                                                        {row[column] === null ? (
                                                                            <span className="text-muted-foreground italic">null</span>
                                                                        ) : (
                                                                            String(row[column])
                                                                        )}
                                                                    </TableCell>
                                                                ))}
                                                            </TableRow>
                                                        ))}
                                                    </TableBody>
                                                </Table>
                                            </div>
                                        )}
                                    </CardContent>
                                </Card>
                            )}
                        </div>

                        <div className="space-y-6">
                            <Card>
                                <CardHeader>
                                    <CardTitle className="text-lg">Common Queries</CardTitle>
                                    <CardDescription>
                                        Click to load into editor
                                    </CardDescription>
                                </CardHeader>
                                <CardContent>
                                    <div className="space-y-2">
                                        {commonQueries.map((commonQuery, index) => (
                                            <Button
                                                key={index}
                                                variant="ghost"
                                                size="sm"
                                                className="w-full justify-start text-left h-auto p-2"
                                                onClick={() => loadQueryFromHistory(commonQuery)}
                                            >
                                                <code className="text-xs">{commonQuery}</code>
                                            </Button>
                                        ))}
                                    </div>
                                </CardContent>
                            </Card>

                            {queryHistory.length > 0 && (
                                <Card>
                                    <CardHeader>
                                        <CardTitle className="text-lg">Query History</CardTitle>
                                        <CardDescription>
                                            Recent queries
                                        </CardDescription>
                                    </CardHeader>
                                    <CardContent>
                                        <div className="space-y-2">
                                            {queryHistory.map((historyItem, index) => (
                                                <div
                                                    key={index}
                                                    className="p-2 rounded border cursor-pointer hover:bg-accent"
                                                    onClick={() => loadQueryFromHistory(historyItem.query)}
                                                >
                                                    <div className="flex items-center justify-between mb-1">
                                                        <Badge
                                                            variant={historyItem.success ? "default" : "destructive"}
                                                            className="text-xs"
                                                        >
                                                            {historyItem.success ? "Success" : "Error"}
                                                        </Badge>
                                                        <div className="text-xs text-muted-foreground">
                                                            {historyItem.timestamp.toLocaleTimeString()}
                                                        </div>
                                                    </div>
                                                    <code className="text-xs text-muted-foreground line-clamp-2">
                                                        {historyItem.query}
                                                    </code>
                                                    {historyItem.executionTime && (
                                                        <div className="text-xs text-muted-foreground mt-1">
                                                            {historyItem.executionTime}ms
                                                        </div>
                                                    )}
                                                </div>
                                            ))}
                                        </div>
                                    </CardContent>
                                </Card>
                            )}
                        </div>
                    </div>
                </div>
            </DashboardLayout>
        </AuthGuard>
    );
}