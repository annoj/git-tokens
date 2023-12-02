package main

import (
	"flag"
	"fmt"
	"git-tokens/scanner"
	"os"
)

func main() {

	addRepoCommand := flag.NewFlagSet("add-repo", flag.ExitOnError)
	addRepoUrl := addRepoCommand.String("url", "", "Repository URL")

	addSecretTypeCommand := flag.NewFlagSet("add-secret-type", flag.ExitOnError)
	addSecretTypeName := addSecretTypeCommand.String("name", "", "Name of the secret type")
	addSecretTypeRegex := addSecretTypeCommand.String("regex", "", "Regex to find the secret")

	// scanRepoCommand := flag.NewFlagSet("scan-repo", flag.ExitOnError)
	// scanRepoUrl := scanRepoCommand.String("url", "", "URL of the repo to scan")

	scanAllCommand := flag.NewFlagSet("scan-all", flag.ExitOnError)

	if len(os.Args) <= 1 {
		fmt.Println("No command given, exiting.")
		os.Exit(1)
	}

	scanner, err := scanner.NewScanner("sqlite3", "git-tokens.slite3")
	if err != nil {
		fmt.Printf("Could not create new scanner, %s\n", err)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "add-repo":
		addRepoCommand.Parse(os.Args[2:])
		fmt.Printf("Adding repo, URL: %s\n", *addRepoUrl)
		err = scanner.AddRepo(*addRepoUrl)
		if err != nil {
			fmt.Printf("Could not add new repo: %s\n", err)
		}
	case "add-secret-type":
		addSecretTypeCommand.Parse(os.Args[2:])
		fmt.Printf("Adding secret type, name: %s, regex: %s\n", *addSecretTypeName, *addSecretTypeRegex)
		err = scanner.AddSecretType(*addSecretTypeName, *addSecretTypeRegex)
		if err != nil {
			fmt.Printf("Could not add secret type: %s\n", err)
		}
	// case "scan-repo":
	// 	scanRepoCommand.Parse(os.Args[2:])
	// 	fmt.Printf("Scanning repo, URL: %s\n", *scanRepoUrl)
	// 	err = scanner.ScanRepo(*scanRepoUrl)
	// 	if err != nil {
	// 		fmt.Printf("Could not scan repo %s,: %s", *scanRepoUrl, err)
	// 	}
	case "scan-all":
		scanAllCommand.Parse(os.Args[2:])
		fmt.Println("Scanning all repos")
		// TODO: Error handling
		scanner.ScanAll()
	}

	if err != nil {
		os.Exit(1)
	}
}
