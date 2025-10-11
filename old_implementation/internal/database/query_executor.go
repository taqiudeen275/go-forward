package database

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// queryExecutor implements the QueryExecutor interface
type queryExecutor struct {
	db             *sql.DB
	runningQueries map[string]*RunningQueryInfo
	queryMutex     sync.RWMutex
	maxConcurrent  int
	defaultTimeout time.Duration
	connectionPool *ConnectionPool
}

// RunningQueryInfo contains information about a running query
type RunningQueryInfo struct {
	QueryID   string
	UserID    string
	Query     string
	StartTime time.Time
	Context   context.Context
	Cancel    context.CancelFunc
	Status    QueryStatus
	Result    chan *SQLQueryResult
	Error     chan error
}

// ConnectionPool manages database connections for query execution
type ConnectionPool struct {
	db          *sql.DB
	maxConns    int
	activeConns int
	connMutex   sync.Mutex
}

// QueryExecutorConfig contains configuration for the query executor
type QueryExecutorConfig struct {
	MaxConcurrentQueries int           `json:"max_concurrent_queries"`
	DefaultTimeout       time.Duration `json:"default_timeout"`
	MaxTimeout           time.Duration `json:"max_timeout"`
	MaxConnections       int           `json:"max_connections"`
	QueryBufferSize      int           `json:"query_buffer_size"`
}

// NewQueryExecutor creates a new query executor instance
func NewQueryExecutor(db *sql.DB) QueryExecutor {
	config := &QueryExecutorConfig{
		MaxConcurrentQueries: 10,
		DefaultTimeout:       30 * time.Second,
		MaxTimeout:           5 * time.Minute,
		MaxConnections:       20,
		QueryBufferSize:      100,
	}

	return NewQueryExecutorWithConfig(db, config)
}

// NewQueryExecutorWithConfig creates a new query executor with custom configuration
func NewQueryExecutorWithConfig(db *sql.DB, config *QueryExecutorConfig) QueryExecutor {
	executor := &queryExecutor{
		db:             db,
		runningQueries: make(map[string]*RunningQueryInfo),
		maxConcurrent:  config.MaxConcurrentQueries,
		defaultTimeout: config.DefaultTimeout,
		connectionPool: &ConnectionPool{
			db:       db,
			maxConns: config.MaxConnections,
		},
	}

	return executor
}

// ExecuteWithTimeout executes a query with the specified timeout
func (e *queryExecutor) ExecuteWithTimeout(query string, timeout time.Duration) (*SQLQueryResult, error) {
	if timeout <= 0 {
		timeout = e.defaultTimeout
	}

	queryID := uuid.New().String()
	startTime := time.Now()

	// Check concurrent query limit
	if err := e.checkConcurrentLimit(); err != nil {
		return nil, fmt.Errorf("concurrent query limit exceeded: %v", err)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Register running query
	queryInfo := &RunningQueryInfo{
		QueryID:   queryID,
		Query:     query,
		StartTime: startTime,
		Context:   ctx,
		Cancel:    cancel,
		Status:    QueryStatusRunning,
		Result:    make(chan *SQLQueryResult, 1),
		Error:     make(chan error, 1),
	}

	e.registerQuery(queryID, queryInfo)
	defer e.unregisterQuery(queryID)

	// Execute query in goroutine
	go e.executeQuery(ctx, queryInfo, query)

	// Wait for result or timeout
	select {
	case result := <-queryInfo.Result:
		queryInfo.Status = QueryStatusCompleted
		result.QueryID = queryID
		result.ExecutionTime = time.Since(startTime)
		return result, nil

	case err := <-queryInfo.Error:
		queryInfo.Status = QueryStatusFailed
		return &SQLQueryResult{
			QueryID:       queryID,
			Success:       false,
			ExecutionTime: time.Since(startTime),
			Error:         err.Error(),
			Metadata: QueryMetadata{
				StartTime: startTime,
				EndTime:   time.Now(),
			},
		}, err

	case <-ctx.Done():
		queryInfo.Status = QueryStatusCancelled
		return &SQLQueryResult{
			QueryID:       queryID,
			Success:       false,
			ExecutionTime: time.Since(startTime),
			Error:         "Query execution timeout",
			Metadata: QueryMetadata{
				StartTime: startTime,
				EndTime:   time.Now(),
			},
		}, fmt.Errorf("query execution timeout after %v", timeout)
	}
}

// ExecuteTransaction executes multiple queries in a transaction
func (e *queryExecutor) ExecuteTransaction(queries []string, timeout time.Duration) (*TransactionResult, error) {
	if timeout <= 0 {
		timeout = e.defaultTimeout * time.Duration(len(queries))
	}

	transactionID := uuid.New().String()
	startTime := time.Now()

	// Check concurrent query limit
	if err := e.checkConcurrentLimit(); err != nil {
		return nil, fmt.Errorf("concurrent query limit exceeded: %v", err)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Get connection from pool
	conn, err := e.connectionPool.getConnection(ctx)
	if err != nil {
		return &TransactionResult{
			TransactionID: transactionID,
			Success:       false,
			ExecutionTime: time.Since(startTime),
			Error:         fmt.Sprintf("Failed to get database connection: %v", err),
		}, err
	}
	defer e.connectionPool.releaseConnection()

	// Begin transaction
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
		ReadOnly:  false,
	})
	if err != nil {
		return &TransactionResult{
			TransactionID: transactionID,
			Success:       false,
			ExecutionTime: time.Since(startTime),
			Error:         fmt.Sprintf("Failed to begin transaction: %v", err),
		}, err
	}

	var results []SQLQueryResult
	var transactionError error

	// Execute queries in transaction
	for i, query := range queries {
		queryStartTime := time.Now()

		// Check if context is cancelled
		select {
		case <-ctx.Done():
			tx.Rollback()
			return &TransactionResult{
				TransactionID: transactionID,
				Success:       false,
				Results:       results,
				ExecutionTime: time.Since(startTime),
				Error:         "Transaction timeout",
			}, fmt.Errorf("transaction timeout")
		default:
		}

		// Execute individual query
		result, err := e.executeQueryInTransaction(ctx, tx, query, i)
		result.ExecutionTime = time.Since(queryStartTime)
		results = append(results, *result)

		if err != nil {
			transactionError = err
			break
		}
	}

	// Commit or rollback transaction
	if transactionError != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			transactionError = fmt.Errorf("transaction failed: %v, rollback failed: %v", transactionError, rollbackErr)
		}

		return &TransactionResult{
			TransactionID: transactionID,
			Success:       false,
			Results:       results,
			ExecutionTime: time.Since(startTime),
			Error:         transactionError.Error(),
		}, transactionError
	}

	if err := tx.Commit(); err != nil {
		return &TransactionResult{
			TransactionID: transactionID,
			Success:       false,
			Results:       results,
			ExecutionTime: time.Since(startTime),
			Error:         fmt.Sprintf("Failed to commit transaction: %v", err),
		}, err
	}

	return &TransactionResult{
		TransactionID: transactionID,
		Success:       true,
		Results:       results,
		ExecutionTime: time.Since(startTime),
	}, nil
}

// CancelQuery cancels a running query
func (e *queryExecutor) CancelQuery(queryID string) error {
	e.queryMutex.RLock()
	queryInfo, exists := e.runningQueries[queryID]
	e.queryMutex.RUnlock()

	if !exists {
		return fmt.Errorf("query %s not found or already completed", queryID)
	}

	if queryInfo.Status != QueryStatusRunning {
		return fmt.Errorf("query %s is not running (status: %s)", queryID, queryInfo.Status)
	}

	// Cancel the query context
	queryInfo.Cancel()
	queryInfo.Status = QueryStatusCancelled

	return nil
}

// GetRunningQueries returns all running queries for a user
func (e *queryExecutor) GetRunningQueries(userID string) ([]RunningQuery, error) {
	e.queryMutex.RLock()
	defer e.queryMutex.RUnlock()

	var queries []RunningQuery

	for _, queryInfo := range e.runningQueries {
		if userID == "" || queryInfo.UserID == userID {
			query := RunningQuery{
				QueryID:     queryInfo.QueryID,
				UserID:      queryInfo.UserID,
				Query:       queryInfo.Query,
				StartTime:   queryInfo.StartTime,
				ElapsedTime: time.Since(queryInfo.StartTime),
				Status:      queryInfo.Status,
				CanCancel:   queryInfo.Status == QueryStatusRunning,
			}
			queries = append(queries, query)
		}
	}

	return queries, nil
}

// Helper methods

func (e *queryExecutor) checkConcurrentLimit() error {
	e.queryMutex.RLock()
	count := len(e.runningQueries)
	e.queryMutex.RUnlock()

	if count >= e.maxConcurrent {
		return fmt.Errorf("maximum concurrent queries (%d) exceeded", e.maxConcurrent)
	}

	return nil
}

func (e *queryExecutor) registerQuery(queryID string, queryInfo *RunningQueryInfo) {
	e.queryMutex.Lock()
	e.runningQueries[queryID] = queryInfo
	e.queryMutex.Unlock()
}

func (e *queryExecutor) unregisterQuery(queryID string) {
	e.queryMutex.Lock()
	delete(e.runningQueries, queryID)
	e.queryMutex.Unlock()
}

func (e *queryExecutor) executeQuery(ctx context.Context, queryInfo *RunningQueryInfo, query string) {
	// Get connection from pool
	conn, err := e.connectionPool.getConnection(ctx)
	if err != nil {
		queryInfo.Error <- fmt.Errorf("failed to get database connection: %v", err)
		return
	}
	defer e.connectionPool.releaseConnection()

	// Determine query type for appropriate execution
	queryType := e.determineQueryType(query)

	var result *SQLQueryResult
	switch queryType {
	case QueryTypeSelect:
		result, err = e.executeSelectQuery(ctx, conn, query)
	case QueryTypeInsert, QueryTypeUpdate, QueryTypeDelete:
		result, err = e.executeModifyQuery(ctx, conn, query)
	case QueryTypeCreate, QueryTypeDrop, QueryTypeAlter:
		result, err = e.executeDDLQuery(ctx, conn, query)
	default:
		result, err = e.executeGenericQuery(ctx, conn, query)
	}

	if err != nil {
		queryInfo.Error <- err
		return
	}

	queryInfo.Result <- result
}

func (e *queryExecutor) executeQueryInTransaction(ctx context.Context, tx *sql.Tx, query string, index int) (*SQLQueryResult, error) {
	queryType := e.determineQueryType(query)

	switch queryType {
	case QueryTypeSelect:
		return e.executeSelectQueryInTx(ctx, tx, query)
	case QueryTypeInsert, QueryTypeUpdate, QueryTypeDelete:
		return e.executeModifyQueryInTx(ctx, tx, query)
	case QueryTypeCreate, QueryTypeDrop, QueryTypeAlter:
		return e.executeDDLQueryInTx(ctx, tx, query)
	default:
		return e.executeGenericQueryInTx(ctx, tx, query)
	}
}

func (e *queryExecutor) executeSelectQuery(ctx context.Context, conn *sql.DB, query string) (*SQLQueryResult, error) {
	rows, err := conn.QueryContext(ctx, query)
	if err != nil {
		return &SQLQueryResult{
			Success: false,
			Error:   err.Error(),
		}, err
	}
	defer rows.Close()

	// Get column names
	columns, err := rows.Columns()
	if err != nil {
		return &SQLQueryResult{
			Success: false,
			Error:   err.Error(),
		}, err
	}

	// Prepare data slice
	var data []map[string]interface{}

	// Scan rows
	for rows.Next() {
		// Create slice for values
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		// Scan row
		if err := rows.Scan(valuePtrs...); err != nil {
			return &SQLQueryResult{
				Success: false,
				Error:   err.Error(),
			}, err
		}

		// Create row map
		row := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]
			if b, ok := val.([]byte); ok {
				row[col] = string(b)
			} else {
				row[col] = val
			}
		}

		data = append(data, row)
	}

	if err := rows.Err(); err != nil {
		return &SQLQueryResult{
			Success: false,
			Error:   err.Error(),
		}, err
	}

	return &SQLQueryResult{
		Success:      true,
		RowsAffected: int64(len(data)),
		Data:         data,
	}, nil
}

func (e *queryExecutor) executeModifyQuery(ctx context.Context, conn *sql.DB, query string) (*SQLQueryResult, error) {
	result, err := conn.ExecContext(ctx, query)
	if err != nil {
		return &SQLQueryResult{
			Success: false,
			Error:   err.Error(),
		}, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		rowsAffected = 0
	}

	return &SQLQueryResult{
		Success:      true,
		RowsAffected: rowsAffected,
	}, nil
}

func (e *queryExecutor) executeDDLQuery(ctx context.Context, conn *sql.DB, query string) (*SQLQueryResult, error) {
	_, err := conn.ExecContext(ctx, query)
	if err != nil {
		return &SQLQueryResult{
			Success: false,
			Error:   err.Error(),
		}, err
	}

	return &SQLQueryResult{
		Success:      true,
		RowsAffected: 0, // DDL queries don't affect rows in the traditional sense
	}, nil
}

func (e *queryExecutor) executeGenericQuery(ctx context.Context, conn *sql.DB, query string) (*SQLQueryResult, error) {
	// Try as modify query first
	result, err := conn.ExecContext(ctx, query)
	if err != nil {
		return &SQLQueryResult{
			Success: false,
			Error:   err.Error(),
		}, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		rowsAffected = 0
	}

	return &SQLQueryResult{
		Success:      true,
		RowsAffected: rowsAffected,
	}, nil
}

// Transaction-specific execution methods
func (e *queryExecutor) executeSelectQueryInTx(ctx context.Context, tx *sql.Tx, query string) (*SQLQueryResult, error) {
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return &SQLQueryResult{
			Success: false,
			Error:   err.Error(),
		}, err
	}
	defer rows.Close()

	// Get column names
	columns, err := rows.Columns()
	if err != nil {
		return &SQLQueryResult{
			Success: false,
			Error:   err.Error(),
		}, err
	}

	// Prepare data slice
	var data []map[string]interface{}

	// Scan rows
	for rows.Next() {
		// Create slice for values
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		// Scan row
		if err := rows.Scan(valuePtrs...); err != nil {
			return &SQLQueryResult{
				Success: false,
				Error:   err.Error(),
			}, err
		}

		// Create row map
		row := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]
			if b, ok := val.([]byte); ok {
				row[col] = string(b)
			} else {
				row[col] = val
			}
		}

		data = append(data, row)
	}

	return &SQLQueryResult{
		Success:      true,
		RowsAffected: int64(len(data)),
		Data:         data,
	}, nil
}

func (e *queryExecutor) executeModifyQueryInTx(ctx context.Context, tx *sql.Tx, query string) (*SQLQueryResult, error) {
	result, err := tx.ExecContext(ctx, query)
	if err != nil {
		return &SQLQueryResult{
			Success: false,
			Error:   err.Error(),
		}, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		rowsAffected = 0
	}

	return &SQLQueryResult{
		Success:      true,
		RowsAffected: rowsAffected,
	}, nil
}

func (e *queryExecutor) executeDDLQueryInTx(ctx context.Context, tx *sql.Tx, query string) (*SQLQueryResult, error) {
	_, err := tx.ExecContext(ctx, query)
	if err != nil {
		return &SQLQueryResult{
			Success: false,
			Error:   err.Error(),
		}, err
	}

	return &SQLQueryResult{
		Success:      true,
		RowsAffected: 0,
	}, nil
}

func (e *queryExecutor) executeGenericQueryInTx(ctx context.Context, tx *sql.Tx, query string) (*SQLQueryResult, error) {
	result, err := tx.ExecContext(ctx, query)
	if err != nil {
		return &SQLQueryResult{
			Success: false,
			Error:   err.Error(),
		}, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		rowsAffected = 0
	}

	return &SQLQueryResult{
		Success:      true,
		RowsAffected: rowsAffected,
	}, nil
}

func (e *queryExecutor) determineQueryType(query string) QueryType {
	// Reuse the logic from validator
	validator := NewSQLValidator()
	parsed, err := validator.ParseQuery(query)
	if err != nil {
		return QueryTypeOther
	}
	return parsed.QueryType
}

// Connection pool methods
func (cp *ConnectionPool) getConnection(ctx context.Context) (*sql.DB, error) {
	cp.connMutex.Lock()
	defer cp.connMutex.Unlock()

	if cp.activeConns >= cp.maxConns {
		return nil, fmt.Errorf("maximum connections (%d) exceeded", cp.maxConns)
	}

	cp.activeConns++
	return cp.db, nil
}

func (cp *ConnectionPool) releaseConnection() {
	cp.connMutex.Lock()
	defer cp.connMutex.Unlock()

	if cp.activeConns > 0 {
		cp.activeConns--
	}
}
