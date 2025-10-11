package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/pkg/errors"
	"github.com/taqiudeen275/go-foward/pkg/logger"
)

// Database represents the database connections
type Database struct {
	PG     *pgxpool.Pool
	Redis  *redis.Client
	config *config.Config
	logger *logger.Logger
}

// New creates a new database instance
func New(cfg *config.Config) (*Database, error) {
	db := &Database{
		config: cfg,
		logger: logger.GetLogger(),
	}

	// Initialize PostgreSQL connection
	if err := db.initPostgreSQL(); err != nil {
		return nil, err
	}

	// Initialize Redis connection
	if err := db.initRedis(); err != nil {
		return nil, err
	}

	return db, nil
}

// initPostgreSQL initializes the PostgreSQL connection pool
func (db *Database) initPostgreSQL() error {
	ctx := context.Background()

	// Build connection string
	connStr := db.config.GetConnectionString()

	// Configure connection pool
	poolConfig, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return errors.NewDatabaseError(fmt.Sprintf("Failed to parse database config: %v", err))
	}

	// Set pool configuration
	poolConfig.MaxConns = int32(db.config.Database.MaxOpenConns)
	poolConfig.MinConns = int32(db.config.Database.MaxIdleConns)
	poolConfig.MaxConnLifetime = db.config.Database.ConnMaxLifetime
	poolConfig.MaxConnIdleTime = db.config.Database.ConnMaxIdleTime

	// Create connection pool
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return errors.NewDatabaseError(fmt.Sprintf("Failed to create connection pool: %v", err))
	}

	// Test connection
	if err := pool.Ping(ctx); err != nil {
		return errors.NewDatabaseError(fmt.Sprintf("Failed to ping database: %v", err))
	}

	db.PG = pool
	db.logger.Info("PostgreSQL connection established",
		"host", db.config.Database.Host,
		"port", db.config.Database.Port,
		"database", db.config.Database.Name,
		"max_conns", db.config.Database.MaxOpenConns,
	)

	return nil
}

// initRedis initializes the Redis connection
func (db *Database) initRedis() error {
	ctx := context.Background()

	// Create Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr:         db.config.GetRedisAddr(),
		Password:     db.config.Redis.Password,
		DB:           db.config.Redis.DB,
		PoolSize:     db.config.Redis.PoolSize,
		MinIdleConns: db.config.Redis.MinIdleConns,
		DialTimeout:  db.config.Redis.DialTimeout,
		ReadTimeout:  db.config.Redis.ReadTimeout,
		WriteTimeout: db.config.Redis.WriteTimeout,
	})

	// Test connection - make Redis optional for development
	if err := rdb.Ping(ctx).Err(); err != nil {
		db.logger.Warn("Redis connection failed, continuing without Redis",
			"host", db.config.Redis.Host,
			"port", db.config.Redis.Port,
			"error", err,
		)
		return nil // Don't fail if Redis is not available
	}

	db.Redis = rdb
	db.logger.Info("Redis connection established",
		"host", db.config.Redis.Host,
		"port", db.config.Redis.Port,
		"db", db.config.Redis.DB,
	)

	return nil
}

// Close closes all database connections
func (db *Database) Close() {
	if db.PG != nil {
		db.PG.Close()
		db.logger.Info("PostgreSQL connection closed")
	}

	if db.Redis != nil {
		db.Redis.Close()
		db.logger.Info("Redis connection closed")
	}
}

// Health checks the health of database connections
func (db *Database) Health(ctx context.Context) map[string]interface{} {
	health := make(map[string]interface{})

	// Check PostgreSQL
	if db.PG != nil {
		if err := db.PG.Ping(ctx); err != nil {
			health["postgresql"] = map[string]interface{}{
				"status": "unhealthy",
				"error":  err.Error(),
			}
		} else {
			stats := db.PG.Stat()
			health["postgresql"] = map[string]interface{}{
				"status":             "healthy",
				"total_conns":        stats.TotalConns(),
				"acquired_conns":     stats.AcquiredConns(),
				"idle_conns":         stats.IdleConns(),
				"constructing_conns": stats.ConstructingConns(),
			}
		}
	}

	// Check Redis
	if db.Redis != nil {
		if err := db.Redis.Ping(ctx).Err(); err != nil {
			health["redis"] = map[string]interface{}{
				"status": "unhealthy",
				"error":  err.Error(),
			}
		} else {
			poolStats := db.Redis.PoolStats()
			health["redis"] = map[string]interface{}{
				"status":      "healthy",
				"hits":        poolStats.Hits,
				"misses":      poolStats.Misses,
				"timeouts":    poolStats.Timeouts,
				"total_conns": poolStats.TotalConns,
				"idle_conns":  poolStats.IdleConns,
			}
		}
	}

	return health
}

// BeginTx starts a new transaction
func (db *Database) BeginTx(ctx context.Context) (pgx.Tx, error) {
	return db.PG.Begin(ctx)
}

// WithTx executes a function within a transaction
func (db *Database) WithTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := db.BeginTx(ctx)
	if err != nil {
		return err
	}

	defer func() {
		if p := recover(); p != nil {
			tx.Rollback(ctx)
			panic(p)
		} else if err != nil {
			tx.Rollback(ctx)
		} else {
			err = tx.Commit(ctx)
		}
	}()

	err = fn(tx)
	return err
}

// ExecuteQuery executes a query and returns the result
func (db *Database) ExecuteQuery(ctx context.Context, query string, args ...interface{}) (pgx.Rows, error) {
	start := time.Now()
	rows, err := db.PG.Query(ctx, query, args...)
	duration := time.Since(start)

	// Log query performance
	db.logger.LogPerformance(ctx, "database_query", duration, map[string]interface{}{
		"query": query,
		"args":  args,
	})

	if err != nil {
		return nil, errors.NewDatabaseError(fmt.Sprintf("Query execution failed: %v", err))
	}

	return rows, nil
}

// ExecuteQueryRow executes a query that returns a single row
func (db *Database) ExecuteQueryRow(ctx context.Context, query string, args ...interface{}) pgx.Row {
	start := time.Now()
	row := db.PG.QueryRow(ctx, query, args...)
	duration := time.Since(start)

	// Log query performance
	db.logger.LogPerformance(ctx, "database_query_row", duration, map[string]interface{}{
		"query": query,
		"args":  args,
	})

	return row
}

// ExecuteExec executes a query that doesn't return rows
func (db *Database) ExecuteExec(ctx context.Context, query string, args ...interface{}) (int64, error) {
	start := time.Now()
	result, err := db.PG.Exec(ctx, query, args...)
	duration := time.Since(start)

	// Log query performance
	db.logger.LogPerformance(ctx, "database_exec", duration, map[string]interface{}{
		"query": query,
		"args":  args,
	})

	if err != nil {
		return 0, errors.NewDatabaseError(fmt.Sprintf("Exec execution failed: %v", err))
	}

	return result.RowsAffected(), nil
}

// Cache operations for Redis
func (db *Database) CacheSet(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return db.Redis.Set(ctx, key, value, expiration).Err()
}

func (db *Database) CacheGet(ctx context.Context, key string) (string, error) {
	return db.Redis.Get(ctx, key).Result()
}

func (db *Database) CacheDel(ctx context.Context, keys ...string) error {
	return db.Redis.Del(ctx, keys...).Err()
}

func (db *Database) CacheExists(ctx context.Context, keys ...string) (int64, error) {
	return db.Redis.Exists(ctx, keys...).Result()
}

// Session operations for Redis
func (db *Database) SetSession(ctx context.Context, sessionID string, data interface{}, expiration time.Duration) error {
	return db.Redis.Set(ctx, fmt.Sprintf("session:%s", sessionID), data, expiration).Err()
}

func (db *Database) GetSession(ctx context.Context, sessionID string) (string, error) {
	return db.Redis.Get(ctx, fmt.Sprintf("session:%s", sessionID)).Result()
}

func (db *Database) DeleteSession(ctx context.Context, sessionID string) error {
	return db.Redis.Del(ctx, fmt.Sprintf("session:%s", sessionID)).Err()
}

// Rate limiting operations for Redis
func (db *Database) IncrementRateLimit(ctx context.Context, key string, window time.Duration) (int64, error) {
	pipe := db.Redis.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, window)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}
	return incr.Val(), nil
}
