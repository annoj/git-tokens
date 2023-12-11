package scanner

import (
	"database/sql"
	"log"
	"os"
	"regexp"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

type Scanner struct {
	dbType           string
	dbPath           string
	db               *sql.DB
	workingDirectory string
	repoPattern      string
}

func (s Scanner) createTablesIfNotExist() error {
	_, err := s.db.Exec(
		`
			CREATE TABLE IF NOT EXISTS repositories (
				url TEXT NOT NULL PRIMARY KEY
			)
		`,
	)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		`
			CREATE TABLE IF NOT EXISTS secret_types (
				name TEXT NOT NULL PRIMARY KEY,
				regex TEXT NOT NULL
			)
		`,
	)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		`
			CREATE TABLE IF NOT EXISTS findings (
				last_scanned_ts TIMESTAMP NOT NULL,
				file_name TEXT NOT NULL,
				line_number INT NOT NULL,
				content TEXT NOT NULL,
				tree_name TEXT NOT NULL,
				repository TEXT NOT NULL,
				secret_type TEXT NOT NULL,
				FOREIGN KEY (secret_type) REFERENCES secret_type(type),
				FOREIGN KEY (repository) REFERENCES repositories(url),
				PRIMARY KEY (repository, tree_name)
			)
		`,
	)

	return err
}

func NewScanner(DBType string, DBPath string) (Scanner, error) {
	scanner := Scanner{
		dbType:           DBType,
		dbPath:           DBPath,
		workingDirectory: ".",
		repoPattern:      "",
	}

	db, err := sql.Open(DBType, DBPath)
	if err != nil {
		return Scanner{}, err
	}
	scanner.db = db

	err = scanner.createTablesIfNotExist()
	if err != nil {
		return Scanner{}, err
	}

	return scanner, nil
}

func (s Scanner) Close() error {
	err := s.db.Close()

	return err
}

func (s Scanner) WorkingDirectory(WorkingDirectory string) {
	s.workingDirectory = WorkingDirectory
}

func (s Scanner) RepoPattern(RepoPattern string) {
	s.repoPattern = RepoPattern
}

func (s Scanner) AddSecretType(Name string, Regex string) error {
	_, err := s.db.Exec(
		`
			INSERT OR IGNORE INTO secret_types (name, regex)
			VALUES (?, ?)
		`,
		Name,
		Regex,
	)

	return err
}

type SecretType struct {
	Name  string
	Regex string
}

func (s Scanner) GetSecretTypes() ([]SecretType, error) {
	rows, err := s.db.Query(
		`
			SELECT name, regex
			FROM secret_types
		`,
	)

	defer rows.Close()

	if err != nil {
		return []SecretType{}, err
	}

	secretTypes := []SecretType{}
	for rows.Next() {
		secretType := SecretType{}
		err := rows.Scan(&secretType.Name, &secretType.Regex)
		if err != nil {
			return []SecretType{}, err
		}
		secretTypes = append(secretTypes, secretType)
	}

	return secretTypes, nil
}

func (s Scanner) AddRepo(URL string) error {
	_, err := s.db.Exec(
		`
			INSERT OR IGNORE INTO repositories(url)
			VALUES (?)
		`,
		URL,
	)

	return err
}

type Repository struct {
	URL string
}

func (s Scanner) GetRepo(URL string) (Repository, error) {
	rows, err := s.db.Query(
		`
			SELECT url
			FROM repositories
			WHERE url == ?
		`,
		URL,
	)

	defer rows.Close()

	if err != nil {
		return Repository{}, err
	}

	repository := Repository{}
	rows.Next()
	err = rows.Scan(&repository.URL)
	if err != nil {
		return Repository{}, err
	}

	return repository, nil
}

func (s Scanner) GetRepos() ([]Repository, error) {
	rows, err := s.db.Query(
		`
			SELECT url
			FROM repositories
		`,
	)

	defer rows.Close()

	if err != nil {
		return []Repository{}, err
	}

	repositories := []Repository{}
	for rows.Next() {
		repository := Repository{}
		err := rows.Scan(&repository.URL)
		if err != nil {
			return []Repository{}, err
		}
		repositories = append(repositories, repository)
	}

	return repositories, nil
}

func (s Scanner) AddFinding(
	URL string,
	SecretTypeName string,
	TreeName string,
	FileName string,
	LineNumber int,
	Content string,
) error {
	_, err := s.db.Exec(
		`
			INSERT OR IGNORE INTO findings (
				last_scanned_ts,
				repository,
				secret_type,
				tree_name,
				file_name,
				line_number,
				content
			)
			VALUES (CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?)
		`,

		URL,
		SecretTypeName,
		TreeName,
		FileName,
		LineNumber,
		Content,
	)

	return err
}

type Finding struct {
	LastScannedTimestamp time.Time
	FileName             string
	LineNumber           int
	Content              string
	TreeName             string
	Repository           string
	SecretType           string
}

func (s Scanner) GetFindings() ([]Finding, error) {
	rows, err := s.db.Query(
		`
			SELECT
				last_scanned_ts,
				file_name,
				line_number,
				content,
				tree_name,
				repository,
				secret_type
			FROM findings
		`,
	)

	defer rows.Close()

	if err != nil {
		return []Finding{}, err
	}

	findings := []Finding{}
	for rows.Next() {
		finding := Finding{}
		err := rows.Scan(
			&finding.LastScannedTimestamp,
			&finding.FileName,
			&finding.LineNumber,
			&finding.Content,
			&finding.TreeName,
			&finding.Repository,
			&finding.SecretType,
		)
		if err != nil {
			return []Finding{}, err
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

func (s Scanner) scanCommit(
	repo *git.Repository,
	url string,
	commitHash plumbing.Hash,
) error {
	secretTypes, err := s.GetSecretTypes()
	if err != nil {
		return err
	}

	for _, secretType := range secretTypes {
		re, err := regexp.Compile(secretType.Regex)
		if err != nil {
			return err
		}

		grepResults, err := repo.Grep(&git.GrepOptions{
			Patterns:   []*regexp.Regexp{re},
			CommitHash: commitHash,
		})
		if err != nil {
			return err
		}

		for _, grepResult := range grepResults {
			err = s.AddFinding(
				url,
				secretType.Name,
				grepResult.TreeName,
				grepResult.FileName,
				grepResult.LineNumber,
				grepResult.Content,
			)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (s Scanner) scanNewCommits(repo *git.Repository, URL string) error {
	handledTreeNames, err := s.db.Query(
		`
			SELECT DISTINCT tree_name
			FROM findings
			WHERE repository = ?
		`,
		URL,
	)
	if err != nil {
		log.Printf("scanNewCommits URL: %s\n", URL)
		return err
	}
	defer handledTreeNames.Close()

	ref, err := repo.Head()
	if err != nil {
		return err
	}

	commitsIter, err := repo.Log(&git.LogOptions{From: ref.Hash()})
	if err != nil {
		return err
	}

	return commitsIter.ForEach(func(commit *object.Commit) error {
		treeName := ""
		for handledTreeNames.Next() {
			if err := handledTreeNames.Scan(&treeName); err != nil {
				log.Printf("scanNewCommits - handleTreeNames.Scan, treeName: %s\n", treeName)
				return err
			}

			if treeName == commit.Hash.String() {
				continue
			}
		}

		return s.scanCommit(repo, URL, commit.Hash)
	})
}

type scanRepoResult struct {
	err error
	url string
}

func (s Scanner) ScanRepo(
	URL string,
	wg *sync.WaitGroup,
) {
	dir, err := os.MkdirTemp(s.workingDirectory, s.repoPattern)
	if err != nil {
		log.Println("ScanRepo - os.MkdirTemp", URL, err)
		wg.Done()
		return
	}
	defer os.RemoveAll(dir)

	repo, err := git.PlainClone(dir, false, &git.CloneOptions{
		URL: URL,
	})
	if err != nil {
		log.Println("ScanRepo - git.PlainClone", URL, err)
		wg.Done()
		return
	}

	if err := s.scanNewCommits(repo, URL); err != nil {
		log.Println("ScanRepo - s.scanNewCommits", URL, err)
		wg.Done()
		return
	}

	// For some reason the first defer statement to remove the
	// temp dir is never executed
	os.RemoveAll(dir)
	wg.Done()
}

func (s Scanner) ScanSingleRepo(URL string) error {
	repo, err := s.GetRepo(URL)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go s.ScanRepo(repo.URL, &wg)
	wg.Wait()

	return nil
}

func (s Scanner) ScanAll() {
	repos, err := s.GetRepos()
	if err != nil {
		log.Println("ScanAll - s.GetRepos", err)
	}

	var wg sync.WaitGroup

	for _, repo := range repos {
		wg.Add(1)
		go s.ScanRepo(repo.URL, &wg)
	}

	wg.Wait()
}

func (s Scanner) scanCommitV2(
	repo *git.Repository,
	repoUrl string,
	commitHash plumbing.Hash,
	secretTypes []SecretType,
	wg *sync.WaitGroup,
) error {
	defer wg.Done()

	log.Printf("Scanning repo %s, commit %s\n", repoUrl, commitHash.String())

	for _, secretType := range secretTypes {
		re, err := regexp.Compile(secretType.Regex)
		if err != nil {
			log.Printf("Could not build regex: %s\n", err)
			return err
		}

		grepResults, err := repo.Grep(&git.GrepOptions{
			Patterns:   []*regexp.Regexp{re},
			CommitHash: commitHash,
		})
		if err != nil {
			log.Printf("Could not grep repo %s: %s\n", repoUrl, err)
			return err
		}

		for _, grepResult := range grepResults {
			err = s.AddFinding(
				repoUrl,
				secretType.Name,
				grepResult.TreeName,
				grepResult.FileName,
				grepResult.LineNumber,
				grepResult.Content,
			)
			if err != nil {
				log.Printf("Could not add finding to database: %s\n", err)
				return err
			}
		}
	}

	return nil
}

func (s Scanner) ScanRepoV2(repoUrl string, wg *sync.WaitGroup) error {
	defer wg.Done()

	scannedCommitsCursor, err := s.db.Query(
		`
			SELECT DISTINCT tree_name
			FROM findings
			WHERE repository = ?

		`,
		repoUrl,
	)
	if err != nil {
		log.Printf(
			"ScanRepoV2: Could not retrieve scanned commits from database: %s\n",
			err,
		)
		return err
	}
	defer scannedCommitsCursor.Close()

	var scannedCommitTreeHashes []string
	for scannedCommitsCursor.Next() {
		var scannedCommitTreeHash = ""
		if err := scannedCommitsCursor.Scan(&scannedCommitTreeHash); err != nil {
			return err
		}
		scannedCommitTreeHashes = append(
			scannedCommitTreeHashes,
			scannedCommitTreeHash,
		)
	}

	dir, err := os.MkdirTemp(s.workingDirectory, s.repoPattern)
	if err != nil {
		log.Printf(
			"Could not create temporary directory %s: %s\n",
			repoUrl,
			err,
		)
		return err
	}
	defer os.RemoveAll(dir)

	log.Printf("Cloning repo %s into %s\n", repoUrl, dir)
	repo, err := git.PlainClone(dir, false, &git.CloneOptions{
		URL: repoUrl,
	})
	if err != nil {
		log.Printf("Could not clone repo %s: %s\n", repoUrl, err)
		return err
	}
	log.Printf("Done cloning repo %s into %s\n", repoUrl, dir)

	ref, err := repo.Head()
	if err != nil {
		log.Printf("Could not retrieve HEAD of %s: %s\n", repoUrl, err)
		return err
	}

	commits, err := repo.Log(&git.LogOptions{From: ref.Hash()})
	if err != nil {
		log.Printf("Could not retrieve commit log of %s: %s\n", repoUrl, err)
		return err
	}

	secretTypes, err := s.GetSecretTypes()
	if err != nil {
		log.Printf("Could not retrieve secret types: %s\n", err)
		return err
	}

	var scanCommitWaitGroup sync.WaitGroup
	commits.ForEach(
		func(commit *object.Commit) error {
			commitHasBeenScanned := false
			for _, scannedCommitTreeHash := range scannedCommitTreeHashes {
				if commit.Hash.String() == scannedCommitTreeHash {
					commitHasBeenScanned = true
					break
				}
			}

			if !commitHasBeenScanned {
				scanCommitWaitGroup.Add(1)
				go s.scanCommitV2(
					repo,
					repoUrl,
					commit.Hash,
					secretTypes,
					&scanCommitWaitGroup,
				)
			}

			return nil
		},
	)

	scanCommitWaitGroup.Wait()

	return nil
}

func (s Scanner) ScanAllV2() error {
	repos, err := s.GetRepos()
	if err != nil {
		return err
	}

	var wg sync.WaitGroup

	for _, repo := range repos {
		wg.Add(1)
		go s.ScanRepoV2(repo.URL, &wg)
	}

	wg.Wait()

	return nil
}
