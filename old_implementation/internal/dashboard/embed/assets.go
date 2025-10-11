package embed

import "embed"

// Static assets for the admin dashboard
//go:embed build/*
var StaticAssets embed.FS

// GetStaticAssets returns the embedded static assets
func GetStaticAssets() embed.FS {
	return StaticAssets
}
