'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useForm, useFieldArray } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { AuthGuard } from '@/components/auth/auth-guard';
import { DashboardLayout } from '@/components/layout/dashboard-layout';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Checkbox } from '@/components/ui/checkbox';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Spinner } from '@/components/ui/spinner';
import { CreateTableRequest, databaseClient, DatabaseError } from '@/lib/database';
import { Plus, Trash2, ArrowLeft } from 'lucide-react';
import Link from 'next/link';

const columnSchema = z.object({
    name: z.string().min(1, 'Column name is required').regex(/^[a-zA-Z_][a-zA-Z0-9_]*$/, 'Invalid column name'),
    type: z.string().min(1, 'Column type is required'),
    nullable: z.boolean(),
    defaultValue: z.string().optional(),
});

const createTableSchema = z.object({
    name: z.string().min(1, 'Table name is required').regex(/^[a-zA-Z_][a-zA-Z0-9_]*$/, 'Invalid table name'),
    schema: z.string().min(1, 'Schema is required'),
    columns: z.array(columnSchema).min(1, 'At least one column is required'),
    primaryKey: z.array(z.string()).optional(),
});

type CreateTableForm = z.infer<typeof createTableSchema>;

const commonTypes = [
    'TEXT',
    'VARCHAR(255)',
    'INTEGER',
    'BIGINT',
    'DECIMAL',
    'BOOLEAN',
    'DATE',
    'TIMESTAMP',
    'TIMESTAMPTZ',
    'UUID',
    'JSON',
    'JSONB',
];

export default function CreateTablePage() {
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const router = useRouter();

    const {
        register,
        control,
        handleSubmit,
        formState: { errors },
        watch,
        setValue,
    } = useForm<CreateTableForm>({
        resolver: zodResolver(createTableSchema),
        defaultValues: {
            name: '',
            schema: 'public',
            columns: [
                { name: 'id', type: 'UUID', nullable: false, defaultValue: 'gen_random_uuid()' },
                { name: 'created_at', type: 'TIMESTAMPTZ', nullable: false, defaultValue: 'NOW()' },
                { name: 'updated_at', type: 'TIMESTAMPTZ', nullable: false, defaultValue: 'NOW()' },
            ],
            primaryKey: ['id'],
        },
    });

    const { fields, append, remove } = useFieldArray({
        control,
        name: 'columns',
    });

    const columns = watch('columns');
    const primaryKey = watch('primaryKey') || [];

    const onSubmit = async (data: CreateTableForm) => {
        try {
            setIsLoading(true);
            setError(null);

            const request: CreateTableRequest = {
                name: data.name,
                schema: data.schema,
                columns: data.columns,
                primaryKey: data.primaryKey?.length ? data.primaryKey : undefined,
            };

            await databaseClient.createTable(request);
            router.push('/dashboard/database');
        } catch (err) {
            if (err instanceof DatabaseError) {
                setError(err.message);
            } else {
                setError('Failed to create table');
            }
        } finally {
            setIsLoading(false);
        }
    };

    const addColumn = () => {
        append({ name: '', type: 'TEXT', nullable: true, defaultValue: '' });
    };

    const togglePrimaryKey = (columnName: string) => {
        const currentPK = primaryKey || [];
        if (currentPK.includes(columnName)) {
            setValue('primaryKey', currentPK.filter(pk => pk !== columnName));
        } else {
            setValue('primaryKey', [...currentPK, columnName]);
        }
    };

    return (
        <AuthGuard>
            <DashboardLayout>
                <div className="space-y-6">
                    <div className="flex items-center space-x-4">
                        <Button asChild variant="outline" size="icon">
                            <Link href="/dashboard/database">
                                <ArrowLeft className="h-4 w-4" />
                            </Link>
                        </Button>
                        <div>
                            <h1 className="text-3xl font-bold">Create Table</h1>
                            <p className="text-muted-foreground">
                                Create a new database table with columns and constraints
                            </p>
                        </div>
                    </div>

                    <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
                        {error && (
                            <Alert variant="destructive">
                                <AlertDescription>{error}</AlertDescription>
                            </Alert>
                        )}

                        <Card>
                            <CardHeader>
                                <CardTitle>Table Information</CardTitle>
                                <CardDescription>
                                    Basic information about the table
                                </CardDescription>
                            </CardHeader>
                            <CardContent className="space-y-4">
                                <div className="grid grid-cols-2 gap-4">
                                    <div className="space-y-2">
                                        <Label htmlFor="name">Table Name</Label>
                                        <Input
                                            id="name"
                                            placeholder="users"
                                            {...register('name')}
                                            disabled={isLoading}
                                        />
                                        {errors.name && (
                                            <p className="text-sm text-destructive">{errors.name.message}</p>
                                        )}
                                    </div>
                                    <div className="space-y-2">
                                        <Label htmlFor="schema">Schema</Label>
                                        <Select
                                            value={watch('schema')}
                                            onValueChange={(value) => setValue('schema', value)}
                                            disabled={isLoading}
                                        >
                                            <SelectTrigger>
                                                <SelectValue />
                                            </SelectTrigger>
                                            <SelectContent>
                                                <SelectItem value="public">public</SelectItem>
                                                <SelectItem value="auth">auth</SelectItem>
                                                <SelectItem value="storage">storage</SelectItem>
                                            </SelectContent>
                                        </Select>
                                        {errors.schema && (
                                            <p className="text-sm text-destructive">{errors.schema.message}</p>
                                        )}
                                    </div>
                                </div>
                            </CardContent>
                        </Card>

                        <Card>
                            <CardHeader>
                                <div className="flex items-center justify-between">
                                    <div>
                                        <CardTitle>Columns</CardTitle>
                                        <CardDescription>
                                            Define the columns for your table
                                        </CardDescription>
                                    </div>
                                    <Button type="button" onClick={addColumn} size="sm" disabled={isLoading}>
                                        <Plus className="mr-2 h-4 w-4" />
                                        Add Column
                                    </Button>
                                </div>
                            </CardHeader>
                            <CardContent>
                                <div className="space-y-4">
                                    {fields.map((field, index) => (
                                        <div key={field.id} className="grid grid-cols-12 gap-4 items-end">
                                            <div className="col-span-3 space-y-2">
                                                <Label htmlFor={`columns.${index}.name`}>Name</Label>
                                                <Input
                                                    {...register(`columns.${index}.name`)}
                                                    placeholder="column_name"
                                                    disabled={isLoading}
                                                />
                                                {errors.columns?.[index]?.name && (
                                                    <p className="text-sm text-destructive">
                                                        {errors.columns[index]?.name?.message}
                                                    </p>
                                                )}
                                            </div>

                                            <div className="col-span-3 space-y-2">
                                                <Label htmlFor={`columns.${index}.type`}>Type</Label>
                                                <Select
                                                    value={columns[index]?.type || ''}
                                                    onValueChange={(value) => setValue(`columns.${index}.type`, value)}
                                                    disabled={isLoading}
                                                >
                                                    <SelectTrigger>
                                                        <SelectValue placeholder="Select type" />
                                                    </SelectTrigger>
                                                    <SelectContent>
                                                        {commonTypes.map((type) => (
                                                            <SelectItem key={type} value={type}>
                                                                {type}
                                                            </SelectItem>
                                                        ))}
                                                    </SelectContent>
                                                </Select>
                                                {errors.columns?.[index]?.type && (
                                                    <p className="text-sm text-destructive">
                                                        {errors.columns[index]?.type?.message}
                                                    </p>
                                                )}
                                            </div>

                                            <div className="col-span-3 space-y-2">
                                                <Label htmlFor={`columns.${index}.defaultValue`}>Default</Label>
                                                <Input
                                                    {...register(`columns.${index}.defaultValue`)}
                                                    placeholder="Default value"
                                                    disabled={isLoading}
                                                />
                                            </div>

                                            <div className="col-span-2 space-y-2">
                                                <div className="space-y-2">
                                                    <div className="flex items-center space-x-2">
                                                        <Checkbox
                                                            id={`columns.${index}.nullable`}
                                                            checked={columns[index]?.nullable || false}
                                                            onCheckedChange={(checked) =>
                                                                setValue(`columns.${index}.nullable`, !!checked)
                                                            }
                                                            disabled={isLoading}
                                                        />
                                                        <Label htmlFor={`columns.${index}.nullable`} className="text-sm">
                                                            Nullable
                                                        </Label>
                                                    </div>
                                                    <div className="flex items-center space-x-2">
                                                        <Checkbox
                                                            id={`pk-${index}`}
                                                            checked={primaryKey.includes(columns[index]?.name || '')}
                                                            onCheckedChange={() => togglePrimaryKey(columns[index]?.name || '')}
                                                            disabled={isLoading || !columns[index]?.name}
                                                        />
                                                        <Label htmlFor={`pk-${index}`} className="text-sm">
                                                            Primary Key
                                                        </Label>
                                                    </div>
                                                </div>
                                            </div>

                                            <div className="col-span-1">
                                                <Button
                                                    type="button"
                                                    variant="outline"
                                                    size="icon"
                                                    onClick={() => remove(index)}
                                                    disabled={isLoading || fields.length === 1}
                                                >
                                                    <Trash2 className="h-4 w-4" />
                                                </Button>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                                {errors.columns && (
                                    <p className="text-sm text-destructive mt-2">
                                        {errors.columns.message}
                                    </p>
                                )}
                            </CardContent>
                        </Card>

                        <div className="flex items-center space-x-4">
                            <Button type="submit" disabled={isLoading}>
                                {isLoading && <Spinner className="mr-2 h-4 w-4" />}
                                Create Table
                            </Button>
                            <Button asChild type="button" variant="outline">
                                <Link href="/dashboard/database">Cancel</Link>
                            </Button>
                        </div>
                    </form>
                </div>
            </DashboardLayout>
        </AuthGuard>
    );
}