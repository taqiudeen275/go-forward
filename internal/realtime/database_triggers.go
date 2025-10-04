package realtime

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TriggerManager manages database triggers for change notifications
type TriggerManager struct {
	pool *pgxpool.Pool
}

// NewTriggerManager creates a new trigger manager
func NewTriggerManager(pool *pgxpool.Pool) *TriggerManager {
	return &TriggerManager{
		pool: pool,
	}
}

// SetupTriggers sets up database triggers for change notifications
func (tm *TriggerManager) SetupTriggers(ctx context.Context, tables []string) error {
	conn, err := tm.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("failed to acquire connection: %v", err)
	}
	defer conn.Release()

	// Create the notification function
	if err := tm.createNotificationFunction(ctx, conn.Conn()); err != nil {
		return fmt.Errorf("failed to create notification function: %v", err)
	}

	// Create triggers for specified tables
	for _, table := range tables {
		if err := tm.createTableTrigger(ctx, conn.Conn(), table); err != nil {
			return fmt.Errorf("failed to create trigger for table %s: %v", table, err)
		}
	}

	return nil
}

// createNotificationFunction creates the PL/pgSQL function for sending notifications
func (tm *TriggerManager) createNotificationFunction(ctx context.Context, conn interface{}) error {
	functionSQL := `
		CREATE OR REPLACE FUNCTION notify_table_changes()
		RETURNS TRIGGER AS $$
		DECLARE
			notification JSON;
			old_record JSON;
			new_record JSON;
		BEGIN
			-- Handle different trigger operations
			IF TG_OP = 'DELETE' THEN
				old_record = row_to_json(OLD);
				new_record = NULL;
			ELSIF TG_OP = 'INSERT' THEN
				old_record = NULL;
				new_record = row_to_json(NEW);
			ELSIF TG_OP = 'UPDATE' THEN
				old_record = row_to_json(OLD);
				new_record = row_to_json(NEW);
			END IF;

			-- Build notification payload
			notification = json_build_object(
				'table', TG_TABLE_NAME,
				'schema', TG_TABLE_SCHEMA,
				'event', TG_OP,
				'old_record', old_record,
				'new_record', new_record,
				'timestamp', extract(epoch from now())
			);

			-- Send notification
			PERFORM pg_notify('table_changes', notification::text);

			-- Return appropriate record
			IF TG_OP = 'DELETE' THEN
				RETURN OLD;
			ELSE
				RETURN NEW;
			END IF;
		END;
		$$ LANGUAGE plpgsql;
	`

	if execer, ok := conn.(interface {
		Exec(context.Context, string, ...interface{}) (interface{}, error)
	}); ok {
		_, err := execer.Exec(ctx, functionSQL)
		return err
	}

	return fmt.Errorf("connection does not support Exec method")
}

// createTableTrigger creates triggers for a specific table
func (tm *TriggerManager) createTableTrigger(ctx context.Context, conn interface{}, tableName string) error {
	// Sanitize table name to prevent SQL injection
	if !isValidTableName(tableName) {
		return fmt.Errorf("invalid table name: %s", tableName)
	}

	triggerSQL := fmt.Sprintf(`
		-- Drop existing trigger if it exists
		DROP TRIGGER IF EXISTS %s_changes_trigger ON %s;

		-- Create new trigger
		CREATE TRIGGER %s_changes_trigger
			AFTER INSERT OR UPDATE OR DELETE ON %s
			FOR EACH ROW
			EXECUTE FUNCTION notify_table_changes();
	`, tableName, tableName, tableName, tableName)

	if execer, ok := conn.(interface {
		Exec(context.Context, string, ...interface{}) (interface{}, error)
	}); ok {
		_, err := execer.Exec(ctx, triggerSQL)
		return err
	}

	return fmt.Errorf("connection does not support Exec method")
}

// RemoveTrigger removes a trigger from a table
func (tm *TriggerManager) RemoveTrigger(ctx context.Context, tableName string) error {
	if !isValidTableName(tableName) {
		return fmt.Errorf("invalid table name: %s", tableName)
	}

	conn, err := tm.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("failed to acquire connection: %v", err)
	}
	defer conn.Release()

	dropSQL := fmt.Sprintf("DROP TRIGGER IF EXISTS %s_changes_trigger ON %s", tableName, tableName)

	_, err = conn.Exec(ctx, dropSQL)
	return err
}

// ListTriggeredTables returns list of tables with change triggers
func (tm *TriggerManager) ListTriggeredTables(ctx context.Context) ([]string, error) {
	conn, err := tm.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire connection: %v", err)
	}
	defer conn.Release()

	query := `
		SELECT DISTINCT event_object_table
		FROM information_schema.triggers
		WHERE trigger_name LIKE '%_changes_trigger'
		AND event_object_schema = 'public'
		ORDER BY event_object_table
	`

	rows, err := conn.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query triggers: %v", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			return nil, fmt.Errorf("failed to scan table name: %v", err)
		}
		tables = append(tables, tableName)
	}

	return tables, nil
}

// SetupTableTriggers sets up triggers for all tables in the public schema
func (tm *TriggerManager) SetupTableTriggers(ctx context.Context) error {
	conn, err := tm.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("failed to acquire connection: %v", err)
	}
	defer conn.Release()

	// Get all tables in public schema
	query := `
		SELECT table_name
		FROM information_schema.tables
		WHERE table_schema = 'public'
		AND table_type = 'BASE TABLE'
		ORDER BY table_name
	`

	rows, err := conn.Query(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to query tables: %v", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			return fmt.Errorf("failed to scan table name: %v", err)
		}
		tables = append(tables, tableName)
	}

	// Setup triggers for all tables
	return tm.SetupTriggers(ctx, tables)
}

// CleanupTriggers removes all change notification triggers
func (tm *TriggerManager) CleanupTriggers(ctx context.Context) error {
	tables, err := tm.ListTriggeredTables(ctx)
	if err != nil {
		return fmt.Errorf("failed to list triggered tables: %v", err)
	}

	for _, table := range tables {
		if err := tm.RemoveTrigger(ctx, table); err != nil {
			return fmt.Errorf("failed to remove trigger from table %s: %v", table, err)
		}
	}

	// Drop the notification function
	conn, err := tm.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("failed to acquire connection: %v", err)
	}
	defer conn.Release()

	_, err = conn.Exec(ctx, "DROP FUNCTION IF EXISTS notify_table_changes()")
	if err != nil {
		return fmt.Errorf("failed to drop notification function: %v", err)
	}

	return nil
}

// isValidTableName validates table name to prevent SQL injection
func isValidTableName(tableName string) bool {
	if tableName == "" || len(tableName) > 63 {
		return false
	}

	// Check for valid characters (alphanumeric, underscores)
	for _, char := range tableName {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '_') {
			return false
		}
	}

	// Must start with letter or underscore
	firstChar := rune(tableName[0])
	if !((firstChar >= 'a' && firstChar <= 'z') ||
		(firstChar >= 'A' && firstChar <= 'Z') ||
		firstChar == '_') {
		return false
	}

	// Check against reserved words (basic list)
	reservedWords := []string{
		"select", "insert", "update", "delete", "drop", "create", "alter",
		"table", "index", "view", "function", "procedure", "trigger",
	}

	lowerName := strings.ToLower(tableName)
	for _, reserved := range reservedWords {
		if lowerName == reserved {
			return false
		}
	}

	return true
}
