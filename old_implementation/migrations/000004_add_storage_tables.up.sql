-- Create buckets table
CREATE TABLE IF NOT EXISTS buckets (
    name VARCHAR(255) PRIMARY KEY,
    config JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create files table
CREATE TABLE IF NOT EXISTS files (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    bucket VARCHAR(255) NOT NULL,
    path TEXT NOT NULL,
    name TEXT NOT NULL,
    size BIGINT NOT NULL DEFAULT 0,
    mime_type VARCHAR(255) NOT NULL DEFAULT 'application/octet-stream',
    checksum VARCHAR(64) NOT NULL,
    metadata JSONB DEFAULT '{}',
    permissions JSONB DEFAULT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT files_bucket_fkey FOREIGN KEY (bucket) REFERENCES buckets(name) ON DELETE CASCADE,
    CONSTRAINT files_bucket_path_unique UNIQUE (bucket, path),
    CONSTRAINT files_size_positive CHECK (size >= 0)
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_files_bucket ON files(bucket);
CREATE INDEX IF NOT EXISTS idx_files_path ON files(path);
CREATE INDEX IF NOT EXISTS idx_files_created_at ON files(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_files_mime_type ON files(mime_type);
CREATE INDEX IF NOT EXISTS idx_files_size ON files(size);

-- Create indexes for JSONB columns
CREATE INDEX IF NOT EXISTS idx_files_metadata ON files USING GIN(metadata);
CREATE INDEX IF NOT EXISTS idx_files_permissions ON files USING GIN(permissions);
CREATE INDEX IF NOT EXISTS idx_buckets_config ON buckets USING GIN(config);

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers to automatically update updated_at
CREATE TRIGGER update_buckets_updated_at 
    BEFORE UPDATE ON buckets 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_files_updated_at 
    BEFORE UPDATE ON files 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Create file_versions table for versioning support
CREATE TABLE IF NOT EXISTS file_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id UUID NOT NULL,
    version INTEGER NOT NULL,
    size BIGINT NOT NULL DEFAULT 0,
    checksum VARCHAR(64) NOT NULL,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT file_versions_file_fkey FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
    CONSTRAINT file_versions_file_version_unique UNIQUE (file_id, version),
    CONSTRAINT file_versions_version_positive CHECK (version > 0),
    CONSTRAINT file_versions_size_positive CHECK (size >= 0)
);

-- Create indexes for file_versions
CREATE INDEX IF NOT EXISTS idx_file_versions_file_id ON file_versions(file_id);
CREATE INDEX IF NOT EXISTS idx_file_versions_version ON file_versions(version DESC);
CREATE INDEX IF NOT EXISTS idx_file_versions_created_at ON file_versions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_file_versions_metadata ON file_versions USING GIN(metadata);

-- Insert default public bucket
INSERT INTO buckets (name, config) 
VALUES ('public', '{"public": true, "max_file_size": 52428800, "allowed_mime_types": [], "versioning": false}')
ON CONFLICT (name) DO NOTHING;