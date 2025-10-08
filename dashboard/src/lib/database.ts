export interface Column {
    name: string;
    type: string;
    nullable: boolean;
    default_value?: string;
    is_primary_key: boolean;
    is_foreign_key: boolean;
    is_unique: boolean;
    ordinal_position: number;
    max_length?: number;
    comment?: string;
}

export interface Index {
    name: string;
    table_name: string;
    columns: string[];
    is_unique: boolean;
    is_primary: boolean;
    index_type: string;
}

export interface Constraint {
    name: string;
    type: 'PRIMARY KEY' | 'FOREIGN KEY' | 'UNIQUE' | 'CHECK';
    table_name: string;
    columns: string[];
    referenced_table?: string;
    referenced_columns?: string[];
}

export interface Table {
    name: string;
    schema: string;
    columns: Column[];
    indexes: Index[];
    constraints: Constraint[];
    rls_enabled: boolean;
    comment?: string;
}

export interface CreateTableRequest {
    name: string;
    schema?: string;
    comment?: string;
    columns: {
        name: string;
        type: string;
        nullable: boolean;
        default_value?: string;
        is_primary_key?: boolean;
        comment?: string;
    }[];
}

export interface UpdateTableRequest {
    add_columns?: {
        name: string;
        type: string;
        nullable: boolean;
        default_value?: string;
        comment?: string;
    }[];
    drop_columns?: string[];
    modify_columns?: {
        name: string;
        new_type?: string;
        set_comment?: string;
    }[];
    rename_columns?: Record<string, string>;
    set_comment?: string;
}

export interface QueryResult {
    columns: string[];
    rows: Record<string, any>[];
    rows_affected: number;
    execution_time: string;
    query_type: string;
}

export class DatabaseError extends Error {
    constructor(
        message: string,
        public code: string,
        public status: number = 400
    ) {
        super(message);
        this.name = 'DatabaseError';
    }
}

export class DatabaseClient {
    private baseUrl: string;

    constructor(baseUrl: string = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080') {
        this.baseUrl = baseUrl;
    }

    private async request<T>(
        endpoint: string,
        options: RequestInit = {}
    ): Promise<T> {
        const url = `${this.baseUrl}${endpoint}`;
        const token = this.getStoredToken();

        console.log(`Making request to: ${url}`);
        console.log(`With token: ${token ? 'Yes' : 'No'}`);

        const response = await fetch(url, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...(token && { Authorization: `Bearer ${token}` }),
                ...options.headers,
            },
        });

        console.log(`Response status: ${response.status}`);

        if (!response.ok) {
            const errorText = await response.text();
            console.log(`Error response: ${errorText}`);

            let error;
            try {
                error = JSON.parse(errorText);
            } catch {
                error = { message: errorText || 'Unknown error' };
            }

            throw new DatabaseError(error.message || error.error || 'Unknown error', error.code || 'UNKNOWN_ERROR', response.status);
        }

        const result = await response.json();
        console.log(`Response data:`, result);
        return result;
    }

    private getStoredToken(): string | null {
        if (typeof window !== 'undefined') {
            return localStorage.getItem('accessToken');
        }
        return null;
    }

    async getTables(schema: string = 'public'): Promise<Table[]> {
        const response = await this.request<{ tables: Table[]; count: number }>(`/database/tables?schemas=${schema}`);
        return response.tables;
    }

    async getTable(tableName: string, schema: string = 'public'): Promise<Table> {
        const response = await this.request<{ table: Table }>(`/database/tables/${schema}/${tableName}`);
        return response.table;
    }

    async createTable(request: CreateTableRequest): Promise<Table> {
        await this.request('/database/tables', {
            method: 'POST',
            body: JSON.stringify(request),
        });
        // Return the created table by fetching it
        return this.getTable(request.name, request.schema || 'public');
    }

    async updateTable(
        tableName: string,
        request: UpdateTableRequest,
        schema: string = 'public'
    ): Promise<Table> {
        await this.request(`/database/tables/${schema}/${tableName}`, {
            method: 'PUT',
            body: JSON.stringify(request),
        });
        // Return the updated table by fetching it
        return this.getTable(tableName, schema);
    }

    async deleteTable(tableName: string, schema: string = 'public'): Promise<void> {
        await this.request(`/database/tables/${schema}/${tableName}`, {
            method: 'DELETE',
        });
    }

    async executeSQL(query: string, args?: any[]): Promise<QueryResult> {
        const cleanQuery = query.trim();

        // Try the exact structure from Postman example first
        console.log('Trying Postman-style request...');
        const postmanBody = { query: cleanQuery };
        console.log('Request body:', JSON.stringify(postmanBody, null, 2));

        try {
            const result = await this.request<QueryResult>('/database/sql/execute', {
                method: 'POST',
                body: JSON.stringify(postmanBody),
            });
            console.log('Postman-style success:', result);
            return result;
        } catch (error) {
            console.error('Postman-style failed:', error);

            // If that fails, try with args if provided
            if (args && args.length > 0) {
                console.log('Trying with args...');
                const argsBody = { query: cleanQuery, args };
                console.log('Args request body:', JSON.stringify(argsBody, null, 2));

                try {
                    const result = await this.request<QueryResult>('/database/sql/execute', {
                        method: 'POST',
                        body: JSON.stringify(argsBody),
                    });
                    console.log('Args request success:', result);
                    return result;
                } catch (argsError) {
                    console.error('Args request failed:', argsError);
                }
            }

            // If all else fails, try the full documentation structure
            console.log('Trying full documentation structure...');
            const fullBody = {
                query: cleanQuery,
                args: args || [],
                options: {
                    max_rows: 1000,
                    read_only: false,
                    transaction: false
                }
            };
            console.log('Full request body:', JSON.stringify(fullBody, null, 2));

            try {
                const result = await this.request<QueryResult>('/database/sql/execute', {
                    method: 'POST',
                    body: JSON.stringify(fullBody),
                });
                console.log('Full request success:', result);
                return result;
            } catch (fullError) {
                console.error('Full request failed:', fullError);
                throw error; // Throw the original error
            }
        }
    }

    async getTableData(
        tableName: string,
        schema: string = 'public',
        options: {
            limit?: number;
            offset?: number;
            orderBy?: string;
            orderDirection?: 'ASC' | 'DESC';
            filters?: Record<string, any>;
        } = {}
    ): Promise<QueryResult> {
        let query = `SELECT * FROM ${schema}.${tableName}`;
        const args: any[] = [];
        let argIndex = 1;

        // Add WHERE conditions for filters
        if (options.filters && Object.keys(options.filters).length > 0) {
            const conditions: string[] = [];
            Object.entries(options.filters).forEach(([key, value]) => {
                if (value !== undefined && value !== null && value !== '') {
                    conditions.push(`${key} = $${argIndex}`);
                    args.push(value);
                    argIndex++;
                }
            });
            if (conditions.length > 0) {
                query += ` WHERE ${conditions.join(' AND ')}`;
            }
        }

        // Add ORDER BY
        if (options.orderBy) {
            query += ` ORDER BY ${options.orderBy} ${options.orderDirection || 'ASC'}`;
        }

        // Add LIMIT and OFFSET
        if (options.limit) {
            query += ` LIMIT $${argIndex}`;
            args.push(options.limit);
            argIndex++;
        }
        if (options.offset) {
            query += ` OFFSET $${argIndex}`;
            args.push(options.offset);
        }

        return this.executeSQL(query, args);
    }

    async insertTableData(
        tableName: string,
        data: Record<string, any>,
        schema: string = 'public'
    ): Promise<Record<string, any>> {
        const columns = Object.keys(data);
        const values = Object.values(data);
        const placeholders = values.map((_, index) => `$${index + 1}`).join(', ');

        const query = `INSERT INTO ${schema}.${tableName} (${columns.join(', ')}) VALUES (${placeholders}) RETURNING *`;
        const result = await this.executeSQL(query, values);

        return result.rows[0] || {};
    }

    async updateTableData(
        tableName: string,
        id: string | number,
        data: Record<string, any>,
        schema: string = 'public'
    ): Promise<Record<string, any>> {
        const columns = Object.keys(data);
        const values = Object.values(data);
        const setClause = columns.map((col, index) => `${col} = $${index + 1}`).join(', ');

        const query = `UPDATE ${schema}.${tableName} SET ${setClause} WHERE id = $${columns.length + 1} RETURNING *`;
        const result = await this.executeSQL(query, [...values, id]);

        return result.rows[0] || {};
    }

    async deleteTableData(
        tableName: string,
        id: string | number,
        schema: string = 'public'
    ): Promise<void> {
        const query = `DELETE FROM ${schema}.${tableName} WHERE id = $1`;
        await this.executeSQL(query, [id]);
    }

    async getSchemas(): Promise<string[]> {
        const response = await this.request<{ schemas: string[]; count: number }>('/database/schemas');
        return response.schemas;
    }

    async getTableStats(tableName: string, schema: string = 'public'): Promise<{
        table: Table;
        row_count: number;
        table_size: string;
        index_size: string;
        total_size: string;
        column_count: number;
        index_count: number;
        constraint_count: number;
    }> {
        return this.request(`/database/tables/${schema}/${tableName}/stats`);
    }

    async validateSQL(query: string, readOnly: boolean = true): Promise<{
        valid: boolean;
        message?: string;
        error?: string;
    }> {
        return this.request('/database/sql/validate', {
            method: 'POST',
            body: JSON.stringify({ query, read_only: readOnly }),
        });
    }
}

export const databaseClient = new DatabaseClient();