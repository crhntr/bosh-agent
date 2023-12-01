package main

import (
	"archive/tar"
	"bufio"
	"cmp"
	"compress/gzip"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"code.cloudfoundry.org/clock"
	boshmodels "github.com/cloudfoundry/bosh-agent/agent/applier/models"
	boshap "github.com/cloudfoundry/bosh-agent/agent/applier/packages"
	boshagentblobstore "github.com/cloudfoundry/bosh-agent/agent/blobstore"
	boshrunner "github.com/cloudfoundry/bosh-agent/agent/cmdrunner"
	boshcomp "github.com/cloudfoundry/bosh-agent/agent/compiler"
	"github.com/cloudfoundry/bosh-agent/agent/httpblobprovider"
	"github.com/cloudfoundry/bosh-agent/agent/httpblobprovider/blobstore_delegator"
	"github.com/cloudfoundry/bosh-agent/app"
	"github.com/cloudfoundry/bosh-agent/settings/directories"
	boshblob "github.com/cloudfoundry/bosh-utils/blobstore"
	boshcrypto "github.com/cloudfoundry/bosh-utils/crypto"
	boshcmd "github.com/cloudfoundry/bosh-utils/fileutil"
	boshlog "github.com/cloudfoundry/bosh-utils/logger"
	boshsys "github.com/cloudfoundry/bosh-utils/system"
)

func main() {
	var outputDirectory string
	flag.StringVar(&outputDirectory, "output-directory", "/tmp", "the directory to put the compiled release tarball")
	flag.Parse()

	if err := os.MkdirAll(outputDirectory, 0o700); err != nil {
		log.Fatal(err)
	}

	stemcellSlug, err := readStemcellSlug()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Compiling with stemcell %s", stemcellSlug)

	dirProvider := directories.NewProvider(app.DefaultBaseDirectory)
	blobsDirectory := dirProvider.BlobsDir()
	log.Printf("writing blobs to %s", blobsDirectory)
	compiler := newCompiler(blobsDirectory, dirProvider)

	if err := os.MkdirAll(blobsDirectory, 0o760); err != nil {
		log.Fatal(err)
	}
	for _, releaseTarballPath := range flag.Args() {
		log.Printf("Reading BOSH Release Manifest from tarball %s", releaseTarballPath)
		m, err := readManifest(releaseTarballPath)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Release %s/%s has %d packages", m.Name, m.Version, len(m.Packages))

		log.Printf("Extracting packages")
		blobstoreIDs, err := extractPackages(m, blobsDirectory, releaseTarballPath)
		if err != nil {
			log.Fatal(err)
		}

		log.Printf("Compiling packages")
		packages := slices.Clone(m.Packages)
		if err := topologicalSort(packages, func(p ReleasePackage) string { return p.Name }, func(p ReleasePackage) []string { return slices.Clone(p.Dependencies) }); err != nil {
			log.Fatal(err)
		}
		var compiledPackages []boshmodels.Package
		for _, p := range packages {
			compiledPackages = compilePackage(p, blobstoreIDs, compiledPackages, compiler)
		}

		log.Printf("Archiving compiled BOSH Release %s/%s with stemcell %s", m.Name, m.Version, stemcellSlug)
		if err := writeCompiledRelease(m, outputDirectory, stemcellSlug, blobsDirectory, releaseTarballPath, compiledPackages); err != nil {
			log.Fatal(err)
		}
	}
}

func writeCompiledRelease(m ReleaseManifest, outputDirectory, stemcellFilenameSuffix, blobsDirectory, initialTarball string, compiledPackages []boshmodels.Package) error {
	fileName := fmt.Sprintf("%s-%s-%s.tgz", m.Name, m.Version, strings.Replace(stemcellFilenameSuffix, "/", "-", 1))
	filePath := filepath.Join(outputDirectory, fileName)
	outputFile, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer closeAndIgnoreErr(outputFile)
	gw := gzip.NewWriter(outputFile)
	defer closeAndIgnoreErr(gw)
	tw := tar.NewWriter(gw)
	defer closeAndIgnoreErr(tw)

	m.CompiledPackages = make([]ReleasePackage, 0, len(compiledPackages))
	for _, p := range compiledPackages {
		m.CompiledPackages = append(m.CompiledPackages, ReleasePackage{
			Name:        p.Name,
			Version:     p.Version,
			Fingerprint: p.Source.BlobstoreID,
			SHA1:        p.Source.Sha1.String(),
			Stemcell:    stemcellFilenameSuffix,
		})
	}

	_, err = readTarballFiles(initialTarball, "", func(fullPath string, info fs.FileInfo, r io.Reader) (bool, error) {
		if strings.HasPrefix(fullPath, "packages/") ||
			info.Name() == releaseManifestFilename {
			return true, nil
		}
		h, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return false, err
		}
		if err := tw.WriteHeader(h); err != nil {
			return false, err
		}
		_, err = io.Copy(tw, r)
		if err != nil {
			return false, err
		}
		return true, nil
	})

	for _, p := range compiledPackages {
		err = copyCompiledTarball(tw, blobsDirectory, p)
		if err != nil {
			return err
		}
	}

	return err
}

func copyCompiledTarball(tw *tar.Writer, blobsDirectory string, p boshmodels.Package) error {
	pkgFilePath := filepath.Join(blobsDirectory, p.Source.BlobstoreID)
	f, err := os.Open(pkgFilePath)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	h, err := tar.FileInfoHeader(fi, "")
	if err != nil {
		return err
	}
	pkgFileName := fmt.Sprintf("%s.tgz", p.Name)
	h.Name = path.Join("compiled_packages", pkgFileName)
	if err := tw.WriteHeader(h); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	if err != nil {
		return err
	}
	return nil
}

func compilePackage(p ReleasePackage, blobstoreIDs map[string]string, compiledPackages []boshmodels.Package, compiler boshcomp.Compiler) []boshmodels.Package {
	log.Printf("Compiling package %s/%s", p.Name, p.Version)
	digest, err := boshcrypto.ParseMultipleDigest(p.SHA1)
	if err != nil {
		log.Fatal(err)
	}
	pkg := boshcomp.Package{
		BlobstoreID: path.Base(blobstoreIDs[p.SHA1]),
		Name:        p.Name,
		Sha1:        digest,
		Version:     p.Version,
	}
	modelsDeps := make([]boshmodels.Package, 0, len(p.Dependencies))
	for _, dep := range p.Dependencies {
		index := slices.IndexFunc(compiledPackages, func(b boshmodels.Package) bool {
			return b.Name == dep
		})
		modelsDeps = append(modelsDeps, compiledPackages[index])
	}
	compiledBlobID, compiledDigest, err := compiler.Compile(pkg, modelsDeps)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Finished compiling release %s/%s BlobstoreID=%s", p.Name, p.Version, compiledBlobID)
	return append(compiledPackages, boshmodels.Package{
		Name:    pkg.Name,
		Version: pkg.Version,
		Source: boshmodels.Source{
			Sha1:        compiledDigest,
			BlobstoreID: compiledBlobID,
		},
	})
}

func newCompiler(localBlobstorePath string, dirProvider directories.Provider) boshcomp.Compiler {
	logger := boshlog.New(boshlog.LevelWarn, log.Default())
	cmdRunner := boshsys.NewExecCmdRunner(logger)
	filesystem := boshsys.NewOsFileSystem(logger)
	compressor := boshcmd.NewTarballCompressor(cmdRunner, filesystem)
	blobstoreProvider := boshblob.NewProvider(
		filesystem,
		cmdRunner,
		dirProvider.EtcDir(),
		logger,
	)
	if err := os.MkdirAll(localBlobstorePath, 0o766); err != nil {
		log.Fatal(err)
	}
	db, err := blobstoreProvider.Get("local", map[string]any{
		"blobstore_path": localBlobstorePath,
	})
	if err != nil {
		log.Fatal(err)
	}
	bd := blobstore_delegator.NewBlobstoreDelegator(
		httpblobprovider.NewHTTPBlobImpl(filesystem, http.DefaultClient),
		boshagentblobstore.NewCascadingBlobstore(db, nil, logger), logger,
	)
	ts := clock.NewClock()
	packageApplierProvider := boshap.NewCompiledPackageApplierProvider(
		dirProvider.DataDir(),
		dirProvider.BaseDir(),
		dirProvider.JobsDir(),
		"packages",
		bd,
		compressor,
		filesystem,
		ts,
		logger,
	)
	return boshcomp.NewConcreteCompiler(
		compressor,
		bd,
		filesystem,
		boshrunner.NewFileLoggingCmdRunner(
			filesystem,
			cmdRunner,
			dirProvider.LogsDir(),
			10*1024, // 10 Kb
		),
		dirProvider,
		packageApplierProvider.Root(),
		packageApplierProvider.RootBundleCollection(),
		ts,
	)
}

func extractPackages(m ReleaseManifest, blobsDirectory, releaseTarballPath string) (map[string]string, error) {
	sha1ToFilepath := make(map[string]string, len(m.Packages))
	if _, err := readTarballFiles(releaseTarballPath, "packages/*.tgz", func(_ string, info fs.FileInfo, src io.Reader) (bool, error) {
		pkgIndex := slices.IndexFunc(m.Packages, func(p ReleasePackage) bool {
			return p.TarballFileName() == path.Base(info.Name())
		})
		if pkgIndex < 0 {
			return true, nil
		}
		p := m.Packages[pkgIndex]
		dstFilepath := filepath.Join(blobsDirectory, p.TarballFileName())
		digest, err := boshcrypto.ParseMultipleDigest(p.SHA1)
		if err != nil {
			return false, err
		}
		dst, err := os.OpenFile(dstFilepath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o640)
		if err != nil {
			return false, err
		}
		defer closeAndIgnoreErr(dst)
		_, err = io.Copy(dst, src)
		log.Printf("Copying package %s to %s", p.Name, dstFilepath)
		if err != nil {
			return false, errors.Join(err, os.RemoveAll(dstFilepath))
		}
		_, err = dst.Seek(0, 0)
		if err != nil {
			return false, errors.Join(err, os.RemoveAll(dstFilepath))
		}
		if err := digest.Verify(dst); err != nil {
			return false, errors.Join(err, os.RemoveAll(dstFilepath))
		}
		sha1ToFilepath[p.SHA1] = dstFilepath
		return true, nil
	}); err != nil {
		return nil, err
	}
	return sha1ToFilepath, nil
}

type ReleaseManifest struct {
	Name               string           `json:"name"`
	Version            string           `json:"version"`
	CommitHash         string           `json:"commit_hash"`
	UncommittedChanges bool             `json:"uncommitted_changes"`
	Jobs               []ReleaseJob     `json:"jobs"`
	Packages           []ReleasePackage `json:"packages,omitempty"`
	CompiledPackages   []ReleasePackage `json:"compiled_packages,omitempty"`
	License            ReleaseLicense   `json:"license"`
}

const releaseManifestFilename = "release.MF"

func readManifest(releaseFilePath string) (ReleaseManifest, error) {
	var m ReleaseManifest
	found, err := readTarballFiles(releaseFilePath, releaseManifestFilename, func(_ string, _ fs.FileInfo, r io.Reader) (bool, error) {
		buf, err := io.ReadAll(r)
		if err != nil {
			return false, err
		}
		return false, yaml.Unmarshal(buf, &m)
	})
	if found < 1 {
		return m, fmt.Errorf("failed to find %s in tarball", releaseManifestFilename)
	}
	return m, err
}

type ReleaseLicense struct {
	Version     string `json:"version"`
	Fingerprint string `json:"fingerprint"`
	Sha1        string `json:"sha1"`
}

type ReleasePackage struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Fingerprint  string   `json:"fingerprint"`
	SHA1         string   `json:"sha1"`
	Stemcell     string   `json:"stemcell,omitempty"`
	Dependencies []string `json:"dependencies"`
}

func (rp ReleasePackage) TarballFileName() string {
	return rp.Name + ".tgz"
}

type ReleaseJob struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Fingerprint string   `json:"fingerprint"`
	Sha1        string   `json:"sha1"`
	Packages    []string `json:"packages"`
}

func closeAndIgnoreErr(c io.Closer) {
	_ = c.Close()
}

func readTarballFiles(releaseFilePath, pattern string, file func(fullName string, info fs.FileInfo, r io.Reader) (bool, error)) (int, error) {
	f, err := os.Open(releaseFilePath)
	if err != nil {
		return 0, nil
	}
	defer closeAndIgnoreErr(f)
	gr, err := gzip.NewReader(bufio.NewReader(f))
	if err != nil {
		return 0, err
	}
	r := tar.NewReader(gr)

	found := 0
	for {
		h, err := r.Next()
		if err != nil {
			if err == io.EOF {
				return found, nil
			}
			return found, err
		}
		info := h.FileInfo()
		if pattern != "" {
			if matches, err := path.Match(pattern, h.Name); err != nil {
				return found, err
			} else if !matches || h.Typeflag != tar.TypeReg || info.IsDir() {
				continue
			}
		}
		found++
		if keepGoing, err := file(h.Name, info, r); err != nil {
			return found, err
		} else if !keepGoing {
			return found, nil
		}
	}
}

func topologicalSort[T any, ID cmp.Ordered, IDFunc func(T) ID, EdgeFunc func(T) []ID](elements []T, elementID IDFunc, elementEdges EdgeFunc) error {
	var (
		visited   = make([]bool, 2*len(elements))
		temporal  = visited[:len(elements)]
		permanent = visited[len(elements):]

		ids    = make(map[ID]int, len(elements))
		sorted = make([]T, 0, len(elements))
	)
	var visit func(ID) error
	visit = func(id ID) error {
		if permanent[ids[id]] {
			return nil
		}
		if temporal[ids[id]] {
			return fmt.Errorf("cycle detected")
		}
		temporal[ids[id]] = true
		e := elements[ids[id]]
		for _, dep := range elementEdges(e) {
			if err := visit(dep); err != nil {
				return err
			}
		}
		sorted = append(sorted, e)
		permanent[ids[id]] = true
		return nil
	}
	slices.SortFunc(elements, func(a, b T) int {
		return cmp.Compare(elementID(a), elementID(b))
	})
	for i, e := range elements {
		ids[elementID(e)] = i
	}
	for _, e := range elements {
		if err := visit(elementID(e)); err != nil {
			return err
		}
	}
	copy(elements, sorted)
	return nil
}
