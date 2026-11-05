package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// PrepareImport reads a bounded regular source through a descriptor-rooted path.
// Importing creates only a proposal; the source path is never publication authority.
func (edit *ModuleEdit) PrepareImport(ctx context.Context, sourcePath string) (*ModuleProposal, error) {
	if edit == nil || edit.state == nil || edit.state.target.relative != "modules/"+userModuleName {
		return nil, errors.New("this operation requires the user override target")
	}
	if ctx == nil {
		return nil, errors.New("configuration import requires a context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(sourcePath) || filepath.Clean(sourcePath) != sourcePath {
		return nil, errors.New("import path must be absolute and canonical")
	}
	content, err := readSecureFileByPathBounded(sourcePath, maximumUserModuleSize)
	if err != nil {
		return nil, fmt.Errorf("read import source securely: %w", err)
	}
	return edit.Prepare(ctx, content)
}

// PrepareProfileName retains unrelated operator bytes and validates the full
// candidate. The caller must still review and approve its publication.
func (edit *ModuleEdit) PrepareProfileName(ctx context.Context, name string) (*ModuleProposal, error) {
	if edit == nil || edit.state == nil || edit.state.target.relative != "modules/"+userModuleName {
		return nil, errors.New("this operation requires the user override target")
	}
	if len(name) == 0 || len(name) > 15 {
		return nil, errors.New("profile name must contain between 1 and 15 ASCII characters")
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == ' ') {
			return nil, errors.New("profile name contains invalid characters")
		}
	}
	return edit.Prepare(ctx, updateProfileInUserModule(edit.Content(), name))
}

// PrepareWithEditor gives the operator-selected editor a private working copy.
// This is not an editor sandbox: the editor runs with the operator's privileges.
func (edit *ModuleEdit) PrepareWithEditor(ctx context.Context, editor func(string) error) (proposal *ModuleProposal, resultErr error) {
	if edit == nil || edit.state == nil || ctx == nil || editor == nil {
		return nil, errors.New("configuration editing requires a captured edit, context and editor")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	name := edit.state.target.name
	directory, err := os.MkdirTemp("", "syswarden-config-edit-")
	if err != nil {
		return nil, err
	}
	root, err := openConfigDirectory(directory, false, 0)
	if err != nil {
		return nil, fmt.Errorf("open private edit directory; retain %s for inspection: %w", directory, err)
	}
	defer func() { _ = root.Close() }()
	identity, err := rootDirectoryInfo(root)
	if err != nil {
		return nil, err
	}
	defer func() {
		// Remove only the fixed working file through the original directory handle.
		// Editor swap/recovery files are retained; never recursively delete the tree.
		cleanupErr := root.Remove(name)
		if errors.Is(cleanupErr, os.ErrNotExist) {
			cleanupErr = nil
		}
		current, statErr := os.Lstat(directory)
		if statErr != nil || !sameFileAndMode(identity, current) {
			cleanupErr = errors.Join(cleanupErr, errors.New("private edit directory identity changed"))
		} else {
			cleanupErr = errors.Join(cleanupErr, os.Remove(directory))
		}
		if cleanupErr != nil {
			proposal = nil
			resultErr = errors.Join(resultErr, fmt.Errorf("private editor files require inspection in %s: %w", directory, cleanupErr))
		}
	}()
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	_, writeErr := file.Write(edit.Content())
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return nil, err
	}
	if err := editor(filepath.Join(directory, name)); err != nil {
		return nil, fmt.Errorf("editor execution failed: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	current, err := os.Lstat(directory)
	if err != nil || !sameFileAndMode(identity, current) {
		return nil, errors.New("private edit directory changed while the editor was running")
	}
	content, _, err := readSecureRegularFileSnapshotBounded(root, name, filepath.Join(directory, name), maximumUserModuleSize)
	if err != nil {
		return nil, fmt.Errorf("read private editor result: %w", err)
	}
	return edit.Prepare(ctx, content)
}
