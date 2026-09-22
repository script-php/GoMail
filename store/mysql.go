package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"gomail/config"

	"github.com/go-sql-driver/mysql"
)

//go:embed schema_mysql.sql
var mysqlSchemaSQL string

// OpenConfig opens the selected backend. Existing configurations default to SQLite.
func OpenConfig(cfg config.StoreConfig) (*DB, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.Database == "sqlite" {
		return Open(cfg.DBPath, cfg.AttachmentsPath)
	}
	return openMySQL(cfg)
}

func (db *DB) IsMySQL() bool { return db.driver == "mysql" }

func mysqlDriverConfig(cfg config.MySQLConfig) *mysql.Config {
	c := mysql.NewConfig()
	c.User, c.Passwd, c.DBName = cfg.User, cfg.Password, cfg.Name
	c.Net, c.Addr = "tcp", net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	c.ParseTime, c.Loc = true, time.UTC
	c.Collation = "utf8mb4_bin"
	c.Params = map[string]string{"time_zone": "'+00:00'"}
	c.TLSConfig = cfg.TLS
	c.Timeout, c.ReadTimeout, c.WriteTimeout = 10*time.Second, 30*time.Second, 30*time.Second
	// Fetch the server's packet limit so large raw messages can use chunked writes.
	c.MaxAllowedPacket = 0
	return c
}

func mysqlConnection(c *mysql.Config) (*sql.DB, error) {
	connector, err := mysql.NewConnector(c)
	if err != nil {
		return nil, fmt.Errorf("configuring MySQL connection: %w", err)
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(3 * time.Minute)
	return db, nil
}

func openMySQL(cfg config.StoreConfig) (*DB, error) {
	if err := os.MkdirAll(cfg.AttachmentsPath, 0750); err != nil {
		return nil, fmt.Errorf("creating attachments directory: %w", err)
	}
	c := mysqlDriverConfig(cfg.MySQL)
	conn, err := mysqlConnection(c)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = conn.PingContext(ctx)
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) && mysqlErr.Number == 1049 {
		// Only request CREATE DATABASE privileges when the selected database is absent.
		conn.Close()
		bootstrap := c.Clone()
		bootstrap.DBName = ""
		admin, openErr := mysqlConnection(bootstrap)
		if openErr != nil {
			return nil, openErr
		}
		_, createErr := admin.ExecContext(ctx, "CREATE DATABASE IF NOT EXISTS "+quoteMySQL(cfg.MySQL.Name)+" CHARACTER SET utf8mb4 COLLATE utf8mb4_bin")
		admin.Close()
		if createErr != nil {
			return nil, fmt.Errorf("creating MySQL database (or create it manually and grant access): %w", createErr)
		}
		conn, err = mysqlConnection(c)
		if err != nil {
			return nil, err
		}
		err = conn.PingContext(ctx)
	}
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("connecting to MySQL: %w", err)
	}
	db := &DB{DB: conn, attachmentsPath: cfg.AttachmentsPath, driver: "mysql"}
	if err := db.initializeMySQL(cfg.MySQL.Name); err != nil {
		conn.Close()
		return nil, err
	}
	return db, nil
}

func quoteMySQL(name string) string { return "`" + strings.ReplaceAll(name, "`", "``") + "`" }

// ExecuteUpsert abstracts SQLite ON CONFLICT vs MySQL ON DUPLICATE KEY for upsert operations.
// For SQLite: uses ON CONFLICT(constraint) DO UPDATE
// For MySQL: uses ON DUPLICATE KEY UPDATE
// The sqliteQuery and mysqlQuery should contain %s placeholders where constraint/columns are inserted.
// Example:
//
//	sqlite := "INSERT INTO users (id, name) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET name = excluded.name"
//	mysql := "INSERT INTO users (id, name) VALUES (?, ?) ON DUPLICATE KEY UPDATE name = VALUES(name)"
//	db.ExecuteUpsert(sqliteQuery, mysqlQuery, args...)
func (db *DB) ExecuteUpsert(sqliteQuery, mysqlQuery string, args ...interface{}) (sql.Result, error) {
	if db.IsMySQL() {
		return db.Exec(mysqlQuery, args...)
	}
	return db.Exec(sqliteQuery, args...)
}

// A dedicated connection keeps the advisory lock across MySQL's implicit DDL commits.
func (db *DB) initializeMySQL(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	lock, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer lock.Close()
	lockName := fmt.Sprintf("gomail-schema-%x", sha256.Sum256([]byte(name)))[:64]
	var acquired sql.NullInt64
	if err := lock.QueryRowContext(ctx, `SELECT GET_LOCK(?, 20)`, lockName).Scan(&acquired); err != nil {
		return fmt.Errorf("locking MySQL migrations: %w", err)
	}
	if !acquired.Valid || acquired.Int64 != 1 {
		return fmt.Errorf("timed out waiting for MySQL migration lock")
	}
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		lock.ExecContext(releaseCtx, `DO RELEASE_LOCK(?)`, lockName)
	}()
	if err := db.syncMySQLSchema(); err != nil {
		return fmt.Errorf("initializing MySQL schema: %w", err)
	}
	return db.runMigrations()
}
