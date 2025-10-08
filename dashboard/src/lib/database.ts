export interface Column {
    name: string;
    type: string;
    nullable: boolean;
    defaultValue?: string;
    isPrimaryKey: boolean;
    isForeignKey: boolean;
    foreignKeyTable?: string;
    foreignKeyColumn?: string;
}

export interface Index {
    name: string;
    columns: string[];
    unique: boolean;
}

export interface Constraint {
    name: string;
    type: 'PRIMARY KEY' | 'FOREIGN KEY' | 'UNIQUE' | 'CHECK';
    columns: string[];
    referencedTable?: string;
    referencedColumns?: string[];
}

export interface Table {
    name: string;
    schema: string;
    columns: Column[];
    indexes: Index[];
    constraints: Constraint[];
    rlsEnabled: boolean;
    rowCount?: number;
}

export interface CreateTableRequest {
    name: string;
    schema?: string;
    columns: Omit<Column, 'isPrimaryKey' | 'isForeignKey'>[];
    primaryKey?: string[];
    indexes?: Omit<Index, 'name'>[];
}

export interface UpdateTableRequest {
    addColumns?: Omit<Column, 'isPrimaryKey' | 'isForeignKey'>[];
    dropColumns?: string[];
    modifyColumns?: {
        name: string;
        newName?: string;
        type?: string;
        nullable?: boolean;
        defaultValue?: string;
    }[];
}

export interface QueryResult {
    columns: string[];
    rows: Record<string, any>[];
    rowCount: number;
    executionTime: number;
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

        const response = await fetch(url, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...(token && { Authorization: `Bearer ${token}` }),
                ...options.headers,
            },
        });

        if (!response.ok) {
            const error = await response.json().catch(() => ({ message: 'Unknown error' }));
            throw new DatabaseError(error.message, error.code || 'UNKNOWN_ERROR', response.status);
        }

        return response.json();
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
        return this.request<QueryResult>('/database/sql/execute', {
            method: 'POST',
            body: JSON.stringify({
                query,
                args: args || [],
                options: {
                    max_rows: 1000,
                    timeout: "30s",
                    read_only: false,
                    transaction: false
                }
            }),
        });
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
        return this.request<Record<string, any>>(`/api/database/tables/${schema}/${tableName}/data`, {
            method: 'POST',
            body: JSON.stringify(data),
        });
    }

    async updateTableData(
        tableName: string,
        id: string | number,
        data: Record<string, any>,
        schema: string = 'public'
    ): Promise<Record<string, any>> {
        return this.request<Record<string, any>>(`/api/database/tables/${schema}/${tableName}/data/${id}`, {
            method: 'PUT',
            body: JSON.stringify(data),
        });
    }

    async deleteTableData(
        tableName: string,
        id: string | number,
        schema: string = 'public'
    ): Promise<void> {
        await this.request(`/api/database/tables/${schema}/${tableName}/data/${id}`, {
            method: 'DELETE',
        });
    }

    async getSchemas(): Promise<string[]> {
        return this.request<string[]>('/api/database/schemas');
    }
}

export const databaseClient = new DatabaseClient();