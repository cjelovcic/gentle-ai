package upgrade

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gentleman-programming/gentle-ai/internal/system"
	"github.com/gentleman-programming/gentle-ai/internal/update"
)

// httpClient is the HTTP client used for asset downloads.
// Package-level var for testability.
var httpClient = &http.Client{Timeout: 5 * time.Minute}

// lookPathFn resolves the binary path. Package-level var for testability.
var lookPathFn = exec.LookPath

// resolveAssetURLFn and resolveChecksumURLFn build download URLs.
// Package-level vars for testability.
var resolveAssetURLFn = resolveAssetURL
var resolveChecksumURLFn = resolveChecksumURL

// cosignLookPathFn checks if cosign is available in PATH. Package-level var for testability.
var cosignLookPathFn = exec.LookPath

// cosignExecFn executes a cosign command. Package-level var for testability.
var cosignExecFn = defaultCosignExec

// resolveCosignSigURLFn and resolveCosignPemURLFn build cosign artifact URLs.
// Package-level vars for testability.
var resolveCosignSigURLFn = resolveCosignSigURL
var resolveCosignPemURLFn = resolveCosignPemURL

func defaultCosignExec(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "cosign", args...)
	cmd.Stdin = nil
	out, err := cmd.CombinedOutput()
	if err != nil {
		first := "(no args)"
		if len(args) > 0 {
			first = args[0]
		}
		return fmt.Errorf("cosign %s: %w (output: %s)", first, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func resolveCosignSigURL(owner, repo, version string) string {
	return fmt.Sprintf("https://github.com/%s/%s/releases/download/v%s/checksums.txt.sig",
		owner, repo, version)
}

func resolveCosignPemURL(owner, repo, version string) string {
	return fmt.Sprintf("https://github.com/%s/%s/releases/download/v%s/checksums.txt.pem",
		owner, repo, version)
}

// verifyCosignSignature verifies the cosign keyless OIDC signature of checksumPath.
// Fails hard if cosign is not installed or if the signature is invalid.
func verifyCosignSignature(ctx context.Context, owner, repo, checksumPath, sigPath, pemPath string) error {
	if _, err := cosignLookPathFn("cosign"); err != nil {
		return fmt.Errorf("cosign not found in PATH — install from https://docs.sigstore.dev/system_config/installation/")
	}
	identityRegexp := fmt.Sprintf("^https://github.com/%s/%s/.github/workflows/", owner, repo)
	return cosignExecFn(ctx,
		"verify-blob",
		"--certificate-identity-regexp", identityRegexp,
		"--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
		"--certificate", pemPath,
		"--signature", sigPath,
		checksumPath,
	)
}

// Download downloads the GitHub release binary for the given tool, verifies its
// cosign signature and SHA256 checksum against the release's checksums.txt, and
// replaces the installed binary atomically.
//
// Checksum verification is mandatory: the install fails if checksums.txt is
// unavailable, if the archive is not listed, or if the digest does not match.
//
// This function is not called on Windows — callers (strategy.go) gate it via
// platform check and return a manual fallback error instead.
func Download(ctx context.Context, r update.UpdateResult, profile system.PlatformProfile) error {
	if profile.OS == "windows" {
		hint := r.UpdateHint
		if hint == "" {
			hint = fmt.Sprintf("Download from https://github.com/%s/%s/releases", r.Tool.Owner, r.Tool.Repo)
		}
		return fmt.Errorf("upgrade %q on Windows requires manual update — %s", r.Tool.Name, hint)
	}

	// Resolve the current binary path from PATH.
	binaryPath, err := lookPathFn(r.Tool.Name)
	if err != nil {
		return fmt.Errorf("locate %q binary: %w", r.Tool.Name, err)
	}

	archiveName := resolveArchiveName(r.Tool.Repo, r.LatestVersion, profile.OS, runtime.GOARCH)
	assetURL := resolveAssetURLFn(r.Tool.Owner, r.Tool.Repo, r.LatestVersion, profile.OS, runtime.GOARCH)
	checksumURL := resolveChecksumURLFn(r.Tool.Owner, r.Tool.Repo, r.LatestVersion)
	cosignSigURL := resolveCosignSigURLFn(r.Tool.Owner, r.Tool.Repo, r.LatestVersion)
	cosignPemURL := resolveCosignPemURLFn(r.Tool.Owner, r.Tool.Repo, r.LatestVersion)

	// Download to a temp directory so we can verify before extracting.
	tmpDir, err := os.MkdirTemp("", "gentle-ai-upgrade-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Step 1: download checksums.txt + cosign artifacts BEFORE the archive.
	// Verifying the signing chain first means we never fetch the large binary
	// from an unsigned or tampered release.
	checksumPath := filepath.Join(tmpDir, "checksums.txt")
	if _, err := downloadToFile(ctx, checksumURL, checksumPath); err != nil {
		return fmt.Errorf("checksum verification failed: checksums.txt unavailable: %w", err)
	}

	sigPath := filepath.Join(tmpDir, "checksums.txt.sig")
	if _, err := downloadToFile(ctx, cosignSigURL, sigPath); err != nil {
		return fmt.Errorf("cosign signature file unavailable (checksums.txt.sig): %w", err)
	}

	pemPath := filepath.Join(tmpDir, "checksums.txt.pem")
	if _, err := downloadToFile(ctx, cosignPemURL, pemPath); err != nil {
		return fmt.Errorf("cosign certificate file unavailable (checksums.txt.pem): %w", err)
	}

	// Step 2: verify cosign signature — fails hard if cosign is not installed.
	if err := verifyCosignSignature(ctx, r.Tool.Owner, r.Tool.Repo, checksumPath, sigPath, pemPath); err != nil {
		return fmt.Errorf("cosign verification failed: %w", err)
	}

	// Step 3: download archive.
	archivePath := filepath.Join(tmpDir, archiveName)
	actualDigest, err := downloadToFile(ctx, assetURL, archivePath)
	if err != nil {
		return fmt.Errorf("download %s: %w", r.Tool.Name, err)
	}

	// Step 4: verify SHA256 — fail closed if mismatched or archive not listed.
	checksumsData, err := os.ReadFile(checksumPath)
	if err != nil {
		return fmt.Errorf("checksum verification failed: read checksums.txt: %w", err)
	}
	expectedDigest, err := expectedChecksumFor(string(checksumsData), archiveName)
	if err != nil {
		return fmt.Errorf("checksum verification failed: %w", err)
	}
	if actualDigest != expectedDigest {
		return fmt.Errorf("checksum mismatch for %s:\n  expected: %s\n  got:      %s",
			archiveName, expectedDigest, actualDigest)
	}

	// Extract the verified binary.
	tmpBinaryPath := binaryPath + ".new"
	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()

	if err := extractBinaryFromTarGz(f, r.Tool.Name, tmpBinaryPath); err != nil {
		_ = os.Remove(tmpBinaryPath)
		return fmt.Errorf("extract %s: %w", r.Tool.Name, err)
	}

	// Atomic replace.
	if err := atomicReplace(tmpBinaryPath, binaryPath); err != nil {
		_ = os.Remove(tmpBinaryPath)
		return fmt.Errorf("replace %q: %w", binaryPath, err)
	}

	return nil
}

// resolveArchiveName returns the GoReleaser archive filename for the given
// repo/version/os/arch combination.
//
// Convention: {repo}_{version}_{os}_{arch}.tar.gz
func resolveArchiveName(repo, version, goos, goarch string) string {
	return fmt.Sprintf("%s_%s_%s_%s.tar.gz", repo, version, goos, goarch)
}

// resolveAssetURL constructs the GitHub Releases asset download URL.
func resolveAssetURL(owner, repo, version, goos, goarch string) string {
	filename := resolveArchiveName(repo, version, goos, goarch)
	return fmt.Sprintf("https://github.com/%s/%s/releases/download/v%s/%s",
		owner, repo, version, filename)
}

// resolveChecksumURL constructs the GitHub Releases URL for checksums.txt.
func resolveChecksumURL(owner, repo, version string) string {
	return fmt.Sprintf("https://github.com/%s/%s/releases/download/v%s/checksums.txt",
		owner, repo, version)
}

// downloadToFile downloads the resource at url to outPath and returns the
// SHA256 hex digest of the downloaded content.
func downloadToFile(ctx context.Context, url string, outPath string) (hexDigest string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return "", fmt.Errorf("create dir: %w", err)
	}
	f, err := os.Create(outPath)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", outPath, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		return "", fmt.Errorf("write %s: %w", outPath, err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// fetchChecksums downloads checksums.txt from url and returns its content.
// Returns an error if the file cannot be fetched or the server returns non-200.
func fetchChecksums(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch checksums.txt: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("checksums.txt: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read checksums.txt: %w", err)
	}
	return string(data), nil
}

// expectedChecksumFor parses checksums.txt content and returns the SHA256 hex
// digest for filename. Returns an error if the filename is not listed.
//
// GoReleaser produces BSD-style checksums.txt: "<digest>  <filename>" per line.
func expectedChecksumFor(content, filename string) (string, error) {
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == filename {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("%q not listed in checksums.txt", filename)
}

// downloadBinary fetches the asset at url, extracts the binary named binaryName
// from the .tar.gz, and writes it to outPath with executable permissions.
//
// Note: this function does not verify checksums. Use Download for a complete,
// checksum-verified upgrade flow.
func downloadBinary(ctx context.Context, url string, binaryName string, outPath string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}

	return extractBinaryFromTarGz(resp.Body, binaryName, outPath)
}

// extractBinaryFromTarGz reads a .tar.gz stream and extracts the first file
// whose base name matches binaryName, writing it to outPath.
func extractBinaryFromTarGz(r io.Reader, binaryName string, outPath string) error {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("open gzip: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}

		// Match by base name (handles subdirectory layouts like tool_1.0_os_arch/tool).
		// Only accept regular files — skip symlinks, hardlinks, and special files.
		if filepath.Base(hdr.Name) == binaryName &&
			(hdr.Typeflag == tar.TypeReg || hdr.Typeflag == tar.TypeRegA) {
			if err := writeExecutable(tr, outPath); err != nil {
				return err
			}
			return nil
		}
	}

	return fmt.Errorf("binary %q not found in archive", binaryName)
}

// writeExecutable writes the content from r to outPath with executable permissions.
func writeExecutable(r io.Reader, outPath string) error {
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return fmt.Errorf("create parent dir: %w", err)
	}

	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("create %s: %w", outPath, err)
	}
	defer f.Close()

	if _, err := io.Copy(f, r); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}

	return nil
}

// atomicReplace moves src to dst atomically using os.Rename.
// This is safe on Unix (same-filesystem rename) but NOT safe on Windows
// when the binary is running. The caller must guard against Windows before calling.
func atomicReplace(src, dst string) error {
	if err := os.Rename(src, dst); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", src, dst, err)
	}
	return nil
}
