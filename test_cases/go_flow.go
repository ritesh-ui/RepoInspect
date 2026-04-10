package main

import (
	"database/sql"
	"fmt"
	"os/exec"
)

/**
 * Enterprise Go Security Test Case
 * Focus: Command Injection and SQL Injection
 */

// Vulnerable Command Injection
func ExecuteUserTask(input string) {
	cmdStr := fmt.Sprintf("echo %s", input)
	cmd := exec.Command("sh", "-c", cmdStr)
	cmd.Run()
}

// Vulnerable SQL Injection
func GetUser(db *sql.DB, userID string) {
	query := "SELECT name FROM users WHERE id = " + userID
	rows, _ := db.Query(query)
	defer rows.Close()
}

// Safe Usage
func SafeBackup() {
	cmd := exec.Command("tar", "cvf", "backup.tar", "/data")
	cmd.Run()
}
