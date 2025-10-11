package template

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/taqiudeen275/go-foward/pkg/errors"
)

// Repository handles template data operations
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository creates a new template repository
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{
		db: db,
	}
}

// Create creates a new template
func (r *Repository) Create(ctx context.Context, template *Template) error {
	template.ID = uuid.New().String()
	template.CreatedAt = time.Now()
	template.UpdatedAt = time.Now()
	template.Version = 1

	// Serialize variables and metadata
	variablesJSON, err := json.Marshal(template.Variables)
	if err != nil {
		return errors.NewValidationError(fmt.Sprintf("Failed to serialize variables: %v", err))
	}

	metadataJSON, err := json.Marshal(template.Metadata)
	if err != nil {
		return errors.NewValidationError(fmt.Sprintf("Failed to serialize metadata: %v", err))
	}

	query := `
		INSERT INTO templates (
			id, type, purpose, language, version, subject, content, 
			variables, is_default, is_active, created_by, created_at, 
			updated_by, updated_at, metadata
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
		)`

	_, err = r.db.Exec(ctx, query,
		template.ID, template.Type, template.Purpose, template.Language,
		template.Version, template.Subject, template.Content, variablesJSON,
		template.IsDefault, template.IsActive, template.CreatedBy,
		template.CreatedAt, template.UpdatedBy, template.UpdatedAt, metadataJSON,
	)

	if err != nil {
		return errors.NewDatabaseError(fmt.Sprintf("Failed to create template: %v", err))
	}

	// Create initial version record
	return r.createVersion(ctx, template, "Initial version")
}

// GetByID retrieves a template by ID
func (r *Repository) GetByID(ctx context.Context, id string) (*Template, error) {
	query := `
		SELECT id, type, purpose, language, version, subject, content, 
			   variables, is_default, is_active, created_by, created_at, 
			   updated_by, updated_at, metadata
		FROM templates 
		WHERE id = $1`

	row := r.db.QueryRow(ctx, query, id)
	return r.scanTemplate(row)
}

// GetByTypeAndPurpose retrieves templates by type and purpose
func (r *Repository) GetByTypeAndPurpose(ctx context.Context, templateType TemplateType, purpose TemplatePurpose, language string) (*Template, error) {
	query := `
		SELECT id, type, purpose, language, version, subject, content, 
			   variables, is_default, is_active, created_by, created_at, 
			   updated_by, updated_at, metadata
		FROM templates 
		WHERE type = $1 AND purpose = $2 AND language = $3 AND is_active = true
		ORDER BY is_default DESC, version DESC
		LIMIT 1`

	row := r.db.QueryRow(ctx, query, templateType, purpose, language)
	template, err := r.scanTemplate(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			// Try to get default language template
			if language != "en" {
				return r.GetByTypeAndPurpose(ctx, templateType, purpose, "en")
			}
			return nil, errors.NewNotFoundError("Template not found")
		}
		return nil, err
	}
	return template, nil
}

// List retrieves templates with filtering
func (r *Repository) List(ctx context.Context, filter *TemplateFilter) ([]*Template, error) {
	query := `
		SELECT id, type, purpose, language, version, subject, content, 
			   variables, is_default, is_active, created_by, created_at, 
			   updated_by, updated_at, metadata
		FROM templates 
		WHERE 1=1`

	args := []interface{}{}
	argIndex := 1

	if filter.Type != nil {
		query += fmt.Sprintf(" AND type = $%d", argIndex)
		args = append(args, *filter.Type)
		argIndex++
	}

	if filter.Purpose != nil {
		query += fmt.Sprintf(" AND purpose = $%d", argIndex)
		args = append(args, *filter.Purpose)
		argIndex++
	}

	if filter.Language != nil {
		query += fmt.Sprintf(" AND language = $%d", argIndex)
		args = append(args, *filter.Language)
		argIndex++
	}

	if filter.IsDefault != nil {
		query += fmt.Sprintf(" AND is_default = $%d", argIndex)
		args = append(args, *filter.IsDefault)
		argIndex++
	}

	if filter.IsActive != nil {
		query += fmt.Sprintf(" AND is_active = $%d", argIndex)
		args = append(args, *filter.IsActive)
		argIndex++
	}

	if filter.CreatedBy != nil {
		query += fmt.Sprintf(" AND created_by = $%d", argIndex)
		args = append(args, *filter.CreatedBy)
		argIndex++
	}

	query += " ORDER BY created_at DESC"

	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, filter.Limit)
		argIndex++
	}

	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIndex)
		args = append(args, filter.Offset)
		argIndex++
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, errors.NewDatabaseError(fmt.Sprintf("Failed to list templates: %v", err))
	}
	defer rows.Close()

	var templates []*Template
	for rows.Next() {
		template, err := r.scanTemplate(rows)
		if err != nil {
			return nil, err
		}
		templates = append(templates, template)
	}

	return templates, nil
}

// Update updates an existing template
func (r *Repository) Update(ctx context.Context, id string, req *TemplateUpdateRequest, updatedBy string) (*Template, error) {
	// Get current template
	current, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Create new version
	newVersion := current.Version + 1

	// Update fields
	if req.Subject != nil {
		current.Subject = req.Subject
	}
	if req.Content != nil {
		current.Content = *req.Content
	}
	if req.Variables != nil {
		current.Variables = req.Variables
	}
	if req.IsActive != nil {
		current.IsActive = *req.IsActive
	}
	if req.Metadata != nil {
		current.Metadata = req.Metadata
	}

	current.Version = newVersion
	current.UpdatedBy = updatedBy
	current.UpdatedAt = time.Now()

	// Serialize variables and metadata
	variablesJSON, err := json.Marshal(current.Variables)
	if err != nil {
		return nil, errors.NewValidationError(fmt.Sprintf("Failed to serialize variables: %v", err))
	}

	metadataJSON, err := json.Marshal(current.Metadata)
	if err != nil {
		return nil, errors.NewValidationError(fmt.Sprintf("Failed to serialize metadata: %v", err))
	}

	query := `
		UPDATE templates 
		SET version = $2, subject = $3, content = $4, variables = $5, 
			is_active = $6, updated_by = $7, updated_at = $8, metadata = $9
		WHERE id = $1`

	_, err = r.db.Exec(ctx, query,
		id, current.Version, current.Subject, current.Content, variablesJSON,
		current.IsActive, current.UpdatedBy, current.UpdatedAt, metadataJSON,
	)

	if err != nil {
		return nil, errors.NewDatabaseError(fmt.Sprintf("Failed to update template: %v", err))
	}

	// Create version record
	changeLog := req.ChangeLog
	if changeLog == "" {
		changeLog = "Template updated"
	}

	err = r.createVersion(ctx, current, changeLog)
	if err != nil {
		return nil, err
	}

	return current, nil
}

// Delete deletes a template
func (r *Repository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM templates WHERE id = $1`

	result, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return errors.NewDatabaseError(fmt.Sprintf("Failed to delete template: %v", err))
	}

	if result.RowsAffected() == 0 {
		return errors.NewNotFoundError("Template not found")
	}

	return nil
}

// GetVersions retrieves all versions of a template
func (r *Repository) GetVersions(ctx context.Context, templateID string) ([]*TemplateVersion, error) {
	query := `
		SELECT id, template_id, version, subject, content, variables, 
			   created_by, created_at, change_log
		FROM template_versions 
		WHERE template_id = $1
		ORDER BY version DESC`

	rows, err := r.db.Query(ctx, query, templateID)
	if err != nil {
		return nil, errors.NewDatabaseError(fmt.Sprintf("Failed to get template versions: %v", err))
	}
	defer rows.Close()

	var versions []*TemplateVersion
	for rows.Next() {
		version, err := r.scanTemplateVersion(rows)
		if err != nil {
			return nil, err
		}
		versions = append(versions, version)
	}

	return versions, nil
}

// GetVersion retrieves a specific version of a template
func (r *Repository) GetVersion(ctx context.Context, templateID string, version int) (*TemplateVersion, error) {
	query := `
		SELECT id, template_id, version, subject, content, variables, 
			   created_by, created_at, change_log
		FROM template_versions 
		WHERE template_id = $1 AND version = $2`

	row := r.db.QueryRow(ctx, query, templateID, version)
	return r.scanTemplateVersion(row)
}

// RecordUsage records template usage statistics
func (r *Repository) RecordUsage(ctx context.Context, templateID string, success bool) error {
	query := `
		INSERT INTO template_usage (template_id, used_at, success)
		VALUES ($1, $2, $3)`

	_, err := r.db.Exec(ctx, query, templateID, time.Now(), success)
	if err != nil {
		return errors.NewDatabaseError(fmt.Sprintf("Failed to record template usage: %v", err))
	}

	return nil
}

// GetStats retrieves template usage statistics
func (r *Repository) GetStats(ctx context.Context, templateID string) (*TemplateStats, error) {
	query := `
		SELECT 
			template_id,
			COUNT(*) as usage_count,
			MAX(used_at) as last_used,
			AVG(CASE WHEN success THEN 1.0 ELSE 0.0 END) as success_rate,
			COUNT(CASE WHEN NOT success THEN 1 END) as failure_count
		FROM template_usage 
		WHERE template_id = $1
		GROUP BY template_id`

	row := r.db.QueryRow(ctx, query, templateID)

	var stats TemplateStats
	var lastUsed sql.NullTime

	err := row.Scan(
		&stats.TemplateID,
		&stats.UsageCount,
		&lastUsed,
		&stats.SuccessRate,
		&stats.FailureCount,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return &TemplateStats{
				TemplateID:   templateID,
				UsageCount:   0,
				LastUsed:     nil,
				SuccessRate:  0,
				FailureCount: 0,
			}, nil
		}
		return nil, errors.NewDatabaseError(fmt.Sprintf("Failed to get template stats: %v", err))
	}

	if lastUsed.Valid {
		stats.LastUsed = &lastUsed.Time
	}

	return &stats, nil
}

// createVersion creates a new version record
func (r *Repository) createVersion(ctx context.Context, template *Template, changeLog string) error {
	variablesJSON, err := json.Marshal(template.Variables)
	if err != nil {
		return errors.NewValidationError(fmt.Sprintf("Failed to serialize variables: %v", err))
	}

	query := `
		INSERT INTO template_versions (
			id, template_id, version, subject, content, variables, 
			created_by, created_at, change_log
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9
		)`

	_, err = r.db.Exec(ctx, query,
		uuid.New().String(), template.ID, template.Version,
		template.Subject, template.Content, variablesJSON,
		template.UpdatedBy, template.UpdatedAt, changeLog,
	)

	if err != nil {
		return errors.NewDatabaseError(fmt.Sprintf("Failed to create template version: %v", err))
	}

	return nil
}

// scanTemplate scans a template from a database row
func (r *Repository) scanTemplate(row pgx.Row) (*Template, error) {
	var template Template
	var variablesJSON, metadataJSON []byte

	err := row.Scan(
		&template.ID, &template.Type, &template.Purpose, &template.Language,
		&template.Version, &template.Subject, &template.Content, &variablesJSON,
		&template.IsDefault, &template.IsActive, &template.CreatedBy,
		&template.CreatedAt, &template.UpdatedBy, &template.UpdatedAt, &metadataJSON,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFoundError("Template not found")
		}
		return nil, errors.NewDatabaseError(fmt.Sprintf("Failed to scan template: %v", err))
	}

	// Deserialize variables
	if len(variablesJSON) > 0 {
		if err := json.Unmarshal(variablesJSON, &template.Variables); err != nil {
			return nil, errors.NewDatabaseError(fmt.Sprintf("Failed to deserialize variables: %v", err))
		}
	}

	// Deserialize metadata
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &template.Metadata); err != nil {
			return nil, errors.NewDatabaseError(fmt.Sprintf("Failed to deserialize metadata: %v", err))
		}
	}

	return &template, nil
}

// scanTemplateVersion scans a template version from a database row
func (r *Repository) scanTemplateVersion(row pgx.Row) (*TemplateVersion, error) {
	var version TemplateVersion
	var variablesJSON []byte

	err := row.Scan(
		&version.ID, &version.TemplateID, &version.Version,
		&version.Subject, &version.Content, &variablesJSON,
		&version.CreatedBy, &version.CreatedAt, &version.ChangeLog,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFoundError("Template version not found")
		}
		return nil, errors.NewDatabaseError(fmt.Sprintf("Failed to scan template version: %v", err))
	}

	// Deserialize variables
	if len(variablesJSON) > 0 {
		if err := json.Unmarshal(variablesJSON, &version.Variables); err != nil {
			return nil, errors.NewDatabaseError(fmt.Sprintf("Failed to deserialize variables: %v", err))
		}
	}

	return &version, nil
}
