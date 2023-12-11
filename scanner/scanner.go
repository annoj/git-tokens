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

type scanResult struct {
	repoUrl    string
	commitHash string
	hasFinding bool
	finding    Finding
}

type Scanner struct {
	dbType           string
	dbPath           string
	db               *sql.DB
	workingDirectory string
	repoPattern      string
	scanResultChan   chan scanResult
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
			CREATE TABLE IF NOT EXISTS scanned_commits (
				repository TEXT NOT NULL,
				commit_hash TEXT NOT NULL,
				last_scanned_ts TIMESTAMP NOT NULL,
				PRIMARY KEY (repository, commit_hash)
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
		scanResultChan:   make(chan scanResult),
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

func (s Scanner) AddScannedCommit(repoUrl string, hash string) error {
	_, err := s.db.Exec(
		`
			INSERT OR IGNORE INTO scanned_commits (
				last_scanned_ts,
				repository,
				commit_hash
			)
			VALUES (CURRENT_TIMESTAMP, ?, ?)
		`,
		repoUrl, hash,
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

func (s Scanner) storeScanResults() {
	log.Println("Starting storeScanResults")

	for result := range s.scanResultChan {
		err := s.AddScannedCommit(result.repoUrl, result.commitHash)
		if err != nil {
			log.Printf(
				"Could not add scanned commit %s %s: %s\n",
				result.repoUrl, result.commitHash, err,
			)
		}

		if result.hasFinding {
			err := s.AddFinding(
				result.finding.Repository,
				result.finding.SecretType,
				result.finding.TreeName,
				result.finding.FileName,
				result.finding.LineNumber,
				result.finding.Content,
			)
			if err != nil {
				log.Printf("Could not add finding: %s\n", err)
			}
		}
	}

	log.Println("Stopping storeScanResults")
}

func (s Scanner) scanCommit(
	repo *git.Repository,
	repoUrl string,
	commitHash plumbing.Hash,
	secretTypes []SecretType,
	wg *sync.WaitGroup,
) error {
	defer func() {
		wg.Done()
		log.Printf("Done scanning repo %s, commit %s\n", repoUrl, commitHash)
	}()

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

		s.scanResultChan <- scanResult{
			repoUrl,
			commitHash.String(),
			false,
			Finding{},
		}

		for _, grepResult := range grepResults {
			s.scanResultChan <- scanResult{
				repoUrl,
				commitHash.String(),
				true,
				Finding{
					time.Time{},
					grepResult.FileName,
					grepResult.LineNumber,
					grepResult.Content,
					grepResult.TreeName,
					repoUrl,
					secretType.Name,
				},
			}
		}
	}

	return nil
}

func (s Scanner) scanRepo(repoUrl string, wg *sync.WaitGroup) error {
	defer wg.Done()

	rows, err := s.db.Query(
		`
			SELECT DISTINCT commit_hash
			FROM scanned_commits
			WHERE repository = ?

		`,
		repoUrl,
	)

	defer rows.Close()

	if err != nil {
		log.Printf(
			"Could not retrieve scanned commits from database: %s\n",
			err,
		)
		return err
	}

	var scannedCommitTreeHashes []string
	for rows.Next() {
		var scannedCommitTreeHash = ""
		if err := rows.Scan(&scannedCommitTreeHash); err != nil {
			log.Printf("Could not retrieve values from row: %s\n", err)
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
				go s.scanCommit(
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
	log.Println("scanCommitWaitGroup has finished")

	return nil
}

func (s Scanner) ScanSingleRepo(repoUrl string) error {
	repo, err := s.GetRepo(repoUrl)
	if err != nil {
		log.Printf("Could not get repo %s: %s\n", repoUrl, err)
		return err
	}

	go s.storeScanResults()

	var wg sync.WaitGroup
	wg.Add(1)
	go s.scanRepo(repo.URL, &wg)
	wg.Wait()

	close(s.scanResultChan)

	return nil
}

func (s Scanner) ScanAll() error {
	repos, err := s.GetRepos()
	if err != nil {
		return err
	}

	go s.storeScanResults()

	var wg sync.WaitGroup
	for _, repo := range repos {
		wg.Add(1)
		go s.scanRepo(repo.URL, &wg)
	}
	wg.Wait()

	close(s.scanResultChan)

	return nil
}
