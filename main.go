package main

import (
	"fmt"
	"git-tokens/scanner"
)

func main() {
	scanner, err := scanner.NewScanner("sqlite3", "db.sqlite3")
	if err != nil {
		panic(err)
	}
	defer scanner.Close()

	err = scanner.AddSecretType(
		"Azure Storage Account SAS Connection String",
		"AccountKey=[a-zA-Z0-9+\\/=]{88}",
	)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = scanner.AddRepo(
		"https://github.com/Azure-Samples/azure-cosmosdb-bulkingestion.git",
	)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = scanner.AddRepo(
		"https://github.com/pablomarin/GPT-Azure-Search-Engine.git",
	)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = scanner.ScanAll()
	if err != nil {
		fmt.Println(err)
		return
	}
}
