package scanner

import (
	"database/sql"
	"os"
	"regexp"

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

func (s Scanner) GetRepos() ([]Repository, error) {
	rows, err := s.db.Query(
		`
			SELECT url
			FROM repositories
		`,
	)
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
				repository,
				secret_type,
				tree_name,
				file_name,
				line_number,
				content
			)
			VALUES (?, ?, ?, ?, ?, ?)
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
				return err
			}

			if treeName == commit.Hash.String() {
				continue
			}
		}

		return s.scanCommit(repo, URL, commit.Hash)
	})
}

func (s Scanner) ScanRepo(URL string) error {
	dir, err := os.MkdirTemp(s.workingDirectory, s.repoPattern)
	if err != nil {
		return err
	}
	defer func() error {
		return os.RemoveAll(dir)
	}()

	repo, err := git.PlainClone(dir, false, &git.CloneOptions{
		URL: URL,
	})
	if err != nil {
		return err
	}

	return s.scanNewCommits(repo, URL)
}

func (s Scanner) ScanAll() error {
	repos, err := s.GetRepos()
	if err != nil {
		return err
	}

	for _, repo := range repos {
		err = s.ScanRepo(repo.URL)
		if err != nil {
			return err
		}
	}

	return nil
}
