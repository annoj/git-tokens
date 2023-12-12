package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"git-tokens/scanner"

	"github.com/mitchellh/cli"
)

const (
	scannerDBType            = "sqlite3"
	scannerDBFilename        = "git-tokens.sqlite3"
	scannerWorkingDirectory  = "."
	scannerRepoDirPattern    = ""
	concurrentScannerWorkers = 100
)

const (
	exitSuccess = iota
	exitMissingSubcommamd
	exitNewScannerError
	exitRepoAddError
	exitRepoListError
	exitSecretTypeAddError
	exitSecretTypeListError
	exitScanAllError
	exitScanRepoError
	exitFindingListError
)

func newScanner() (*scanner.Scanner, error) {
	return scanner.NewScanner(
		scannerDBType,
		scannerDBFilename,
		scannerWorkingDirectory,
		scannerRepoDirPattern,
		concurrentScannerWorkers,
	)
}

func confirmRawArgsLenOrLogError(
	args []string,
	arglen int,
	help func() string,
) bool {
	if len(args) != arglen {
		log.Printf(
			"Wrong number of arguments\n%s\n",
			help(),
		)
		return false
	}

	return true
}

type repoCommand struct{}

func (c repoCommand) Run(rawArgs []string) int {
	fmt.Printf(
		"Missing subcommand\n%s\n",
		c.Help(),
	)

	return exitMissingSubcommamd
}

func (c repoCommand) Help() string {
	return "Usage: git-tokens repo [add | list]"
}

func (c repoCommand) Synopsis() string {
	return "Manage repositories"
}

type repoAddCommand struct{}

func (c repoAddCommand) Run(rawArgs []string) int {
	if !confirmRawArgsLenOrLogError(rawArgs, 1, c.Help) {
		return exitRepoAddError
	}

	scanner, err := newScanner()
	if err != nil {
		log.Printf("Could not create new scanner, %s\n", err)
		return exitNewScannerError
	}

	repoUrl := rawArgs[0]
	log.Printf("Adding repo %s\n", repoUrl)
	err = scanner.AddRepo(repoUrl)
	if err != nil {
		log.Printf("Could not add repo: %s\n", err)
		return exitRepoAddError
	}

	return exitSuccess
}

func (c repoAddCommand) Help() string {
	return "Usage: git-tokens repo add <repo-url>"
}

func (c repoAddCommand) Synopsis() string {
	return "Add repository to database"
}

type repoListCommand struct{}

func (c repoListCommand) Run(rawArgs []string) int {
	if !confirmRawArgsLenOrLogError(rawArgs, 0, c.Help) {
		return exitRepoListError
	}

	scanner, err := newScanner()
	if err != nil {
		log.Printf("Could not create new scanner, %s\n", err)
		return exitNewScannerError
	}

	repos, err := scanner.GetRepos()
	if err != nil {
		log.Printf("Could not get repos, %s\n", err)
		return exitRepoListError
	}

	for _, repo := range repos {
		fmt.Println(repo.URL)
	}

	return exitSuccess
}

func (c repoListCommand) Help() string {
	return "Usage: git-tokens repo list"
}

func (c repoListCommand) Synopsis() string {
	return "List all repos in database"
}

type secretTypeCommand struct{}

func (c secretTypeCommand) Run(rawArgs []string) int {
	fmt.Printf(
		"Missing subcommand\n%s\n",
		c.Help(),
	)

	return exitMissingSubcommamd
}

func (c secretTypeCommand) Help() string {
	return "git-tokens secret-type [add | list]"
}

func (c secretTypeCommand) Synopsis() string {
	return "Manage secret types"
}

type secretTypeAddCommand struct{}

func (c secretTypeAddCommand) Run(rawArgs []string) int {
	if !confirmRawArgsLenOrLogError(rawArgs, 2, c.Help) {
		return exitSecretTypeAddError
	}

	scanner, err := newScanner()
	if err != nil {
		log.Printf("Could not create new scanner, %s\n", err)
		return exitNewScannerError
	}

	secretTypeName := rawArgs[0]
	secretTypeRegex := rawArgs[1]
	log.Printf("Adding secret type \"%s\": \"%s\"", secretTypeName, secretTypeRegex)
	err = scanner.AddSecretType(secretTypeName, secretTypeRegex)
	if err != nil {
		log.Printf("Could not add secret type: %s\n", err)
		return exitSecretTypeAddError
	}

	return exitSuccess
}

func (c secretTypeAddCommand) Help() string {
	return "Usage: git-secrets secret-type add <secret type name> <secret type regex>"
}

func (c secretTypeAddCommand) Synopsis() string {
	return "Add secret types to database"
}

type secretTypeListCommand struct{}

func (c secretTypeListCommand) Run(rawArgs []string) int {
	if !confirmRawArgsLenOrLogError(rawArgs, 0, c.Help) {
		return exitSecretTypeListError
	}

	scanner, err := newScanner()
	if err != nil {
		log.Printf("Could not create new scanner, %s\n", err)
		return exitNewScannerError
	}

	secretTypes, err := scanner.GetSecretTypes()
	if err != nil {
		log.Printf("Could not get secret types: %s\n", err)
		return exitSecretTypeListError
	}

	for _, secretType := range secretTypes {
		fmt.Printf("%s\t%s\n", secretType.Name, secretType.Regex)
	}

	return exitSuccess
}

func (c secretTypeListCommand) Help() string {
	return "Usage git-tokens secret-type get"
}

func (c secretTypeListCommand) Synopsis() string {
	return "List all secret types in databas"
}

type scanCommand struct{}

func (c scanCommand) Run(rawArgs []string) int {
	fmt.Printf(
		"Missing subcommand\n%s\n",
		c.Help(),
	)

	return exitMissingSubcommamd
}

func (c scanCommand) Help() string {
	return "Usage: git-secrets scan [all | repo]"
}

func (c scanCommand) Synopsis() string {
	return "Scan all or a single repo"
}

type scanAllCommand struct{}

func (c scanAllCommand) Run(rawArgs []string) int {
	if !confirmRawArgsLenOrLogError(rawArgs, 0, c.Help) {
		return exitScanAllError
	}

	scanner, err := newScanner()
	if err != nil {
		log.Printf("Could not create new scanner: %s\n", err)
		return exitNewScannerError
	}

	log.Printf("Scanning all repos\n")
	err = scanner.ScanAll()
	if err != nil {
		log.Printf("Could not scan repos: %s\n", err)
		return exitScanAllError
	}

	return exitSuccess
}

func (c scanAllCommand) Help() string {
	return "Usage: git-secrets scan all"
}

func (c scanAllCommand) Synopsis() string {
	return "Scan all new commits in all repos"
}

type scanRepoCommand struct{}

func (c scanRepoCommand) Run(rawArgs []string) int {
	if !confirmRawArgsLenOrLogError(rawArgs, 1, c.Help) {
		return exitScanRepoError
	}

	scanner, err := newScanner()
	if err != nil {
		log.Printf("Could not create new scanner, %s\n", err)
		return exitNewScannerError
	}

	repoUrl := rawArgs[0]
	err = scanner.ScanSingleRepo(repoUrl)
	if err != nil {
		log.Printf("Could not scan repo %s: %s\n", repoUrl, err)
		return exitScanRepoError
	}

	return exitSuccess
}

func (c scanRepoCommand) Help() string {
	return "Usage: git-tokens scan repo <repo url>"
}

func (c scanRepoCommand) Synopsis() string {
	return "Scan single repository"
}

type findingCommand struct{}

func (c findingCommand) Run(rawArgs []string) int {
	fmt.Printf(
		"Missing subcommand\n%s\n",
		c.Help(),
	)

	return exitMissingSubcommamd
}

func (c findingCommand) Help() string {
	return "Usage: git-tokens finding [list]"
}

func (c findingCommand) Synopsis() string {
	return "Manage findings"
}

type findingListCommand struct{}

func (c findingListCommand) Run(rawArgs []string) int {
	if !confirmRawArgsLenOrLogError(rawArgs, 0, c.Help) {
		return exitFindingListError
	}

	scanner, err := newScanner()
	if err != nil {
		log.Printf("Could not create new scanner, %s\n", err)
		return exitNewScannerError
	}

	findings, err := scanner.GetFindings()
	if err != nil {
		log.Printf("Could not get findings: %s\n", err)
		return exitFindingListError
	}

	for _, finding := range findings {
		fmt.Printf(
			"%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
			finding.LastScannedTimestamp.Format(time.RFC822Z),
			finding.FileName,
			finding.LineNumber,
			finding.Content,
			finding.TreeName,
			finding.Repository,
			finding.SecretType,
		)
	}

	return exitSuccess
}

func (c findingListCommand) Help() string {
	return "Usage: git-tokens finding list"
}

func (c findingListCommand) Synopsis() string {
	return "List all findings"
}

func main() {
	c := cli.NewCLI("git-token", "1.0.0")
	c.Args = os.Args[1:]
	c.Commands = map[string]cli.CommandFactory{
		"repo": func() (cli.Command, error) {
			return repoCommand{}, nil
		},

		"repo add": func() (cli.Command, error) {
			return repoAddCommand{}, nil
		},

		// TODO: Add "repo remove"

		"repo list": func() (cli.Command, error) {
			return repoListCommand{}, nil
		},

		"secret-type": func() (cli.Command, error) {
			return secretTypeCommand{}, nil
		},

		"secret-type add": func() (cli.Command, error) {
			return secretTypeAddCommand{}, nil
		},

		// TODO: Add "secret-type remove"

		"secret-type list": func() (cli.Command, error) {
			return secretTypeListCommand{}, nil
		},

		"scan": func() (cli.Command, error) {
			return scanCommand{}, nil
		},

		"scan all": func() (cli.Command, error) {
			return scanAllCommand{}, nil
		},

		"scan repo": func() (cli.Command, error) {
			return scanRepoCommand{}, nil
		},

		"finding": func() (cli.Command, error) {
			return findingCommand{}, nil
		},

		"finding list": func() (cli.Command, error) {
			return findingListCommand{}, nil
		},
	}

	exitStatus, err := c.Run()
	if err != nil {
		log.Println(err)
	}

	log.Printf("Done.")

	os.Exit(exitStatus)
}
