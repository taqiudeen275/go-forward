'use client';

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { databaseClient } from '@/lib/database';

export function DatabaseDebug() {
    const [results, setResults] = useState<string[]>([]);
    const [loading, setLoading] = useState(false);

    const addResult = (message: string) => {
        setResults(prev => [...prev, `${new Date().toLocaleTimeString()}: ${message}`]);
    };

    const testBasicConnection = async () => {
        setLoading(true);
        addResult('Testing basic connection...');

        try {
            // Test direct fetch to the endpoint
            const response = await fetch('http://localhost:8080/database/schemas');
            addResult(`Direct fetch status: ${response.status}`);

            if (response.ok) {
                const data = await response.json();
                addResult(`Direct fetch success: ${JSON.stringify(data)}`);
            } else {
                const errorText = await response.text();
                addResult(`Direct fetch error: ${errorText}`);
            }
        } catch (error) {
            addResult(`Direct fetch failed: ${error}`);
        }

        setLoading(false);
    };

    const testWithClient = async () => {
        setLoading(true);
        addResult('Testing with database client...');

        try {
            const schemas = await databaseClient.getSchemas();
            addResult(`Client success: ${JSON.stringify(schemas)}`);
        } catch (error) {
            addResult(`Client error: ${error}`);
        }

        setLoading(false);
    };

    const testSimpleSQL = async () => {
        setLoading(true);
        addResult('Testing simple SQL...');

        try {
            const result = await databaseClient.executeSQL('SELECT 1 as test');
            addResult(`SQL success: ${JSON.stringify(result)}`);
        } catch (error) {
            addResult(`SQL error: ${error}`);
        }

        setLoading(false);
    };

    const testDirectSQL = async () => {
        setLoading(true);
        addResult('Testing direct SQL fetch...');

        try {
            const response = await fetch('http://localhost:8080/database/sql/execute', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    query: 'SELECT 1 as test'
                })
            });

            addResult(`Direct SQL status: ${response.status}`);

            if (response.ok) {
                const data = await response.json();
                addResult(`Direct SQL success: ${JSON.stringify(data)}`);
            } else {
                const errorText = await response.text();
                addResult(`Direct SQL error: ${errorText}`);
            }
        } catch (error) {
            addResult(`Direct SQL failed: ${error}`);
        }

        setLoading(false);
    };

    const clearResults = () => {
        setResults([]);
    };

    return (
        <Card className="w-full max-w-4xl">
            <CardHeader>
                <CardTitle>Database Connection Debug</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
                <div className="flex flex-wrap gap-2">
                    <Button onClick={testBasicConnection} disabled={loading}>
                        Test Basic Connection
                    </Button>
                    <Button onClick={testWithClient} disabled={loading}>
                        Test With Client
                    </Button>
                    <Button onClick={testSimpleSQL} disabled={loading}>
                        Test Simple SQL
                    </Button>
                    <Button onClick={testDirectSQL} disabled={loading}>
                        Test Direct SQL
                    </Button>
                    <Button onClick={clearResults} variant="outline">
                        Clear Results
                    </Button>
                </div>

                <div className="space-y-2 max-h-96 overflow-y-auto">
                    {results.map((result, index) => (
                        <Alert key={index}>
                            <AlertDescription className="font-mono text-sm">
                                {result}
                            </AlertDescription>
                        </Alert>
                    ))}
                </div>
            </CardContent>
        </Card>
    );
}