package cmd

import (
	"flag"
	"fmt"
	"go-tech/config"
	"go-tech/internal/app/appcontext"
	"go-tech/internal/app/commons"
	"go-tech/internal/app/constant"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var migrateUpCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Migrate Up DB",
	Long:  `Please you know what are you doing by using this command`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := config.Config()
		logger := initLogger(cfg)

		app := appcontext.NewAppContext(cfg)

		opt := commons.InitCommonOptions(
			commons.WithConfig(cfg),
			commons.WithLogger(logger),
			commons.WithDB(app),
		)

		runMigration(opt, constant.MigrateUp)
	},
}

var migrateDownCmd = &cobra.Command{
	Use:   "migratedown",
	Short: "Migrate Up DB",
	Long:  `Please you know what are you doing by using this command`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := config.Config()
		logger := initLogger(cfg)

		opt := commons.InitCommonOptions(
			commons.WithConfig(cfg),
			commons.WithLogger(logger),
		)

		runMigration(opt, constant.MigrateDown)
	},
}

func init() {
	rootCmd.AddCommand(migrateUpCmd)
	rootCmd.AddCommand(migrateDownCmd)
}

func runMigration(opt *commons.Options, direction int) {
	pathMigration := opt.Config.AppMigrationPath
	migrationDir := flag.String("migration-dir", pathMigration, "migration directory")
	opt.Logger.Info("path migration : " + pathMigration)
	switch direction {
	case constant.MigrateUp:
		migrateUp(opt, *migrationDir)
		break
	case constant.MigrateDown:
		migrateDown(opt, *migrationDir)
		break
	default:
		opt.Logger.Info("Unknown migration direction")
		break
	}
}

func migrateUp(opt *commons.Options, migrationDir string) {
	opt.Logger.Info("Migrating up database ...")
	db, err := opt.DB.DB()
	if err != nil {
		opt.Logger.Error("Error get SQL DB", zap.Error(err))
		return
	}
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		opt.Logger.Error("Driver error", zap.Error(err))
		return
	}

	migrateDatabase, err := migrate.NewWithDatabaseInstance(
		fmt.Sprintf("file://%s", migrationDir),
		"postgres", driver)
	if err != nil {
		opt.Logger.Error("Migrate error", zap.Error(err))
		return
	}

	err = migrateDatabase.Up()
	if err != nil {
		opt.Logger.Error("Migrate up error", zap.Error(err))
		return
	}

	opt.Logger.Info("Migration done ...")

	//Get latest version
	version, dirty, errVersion := migrateDatabase.Version()
	//Ignore error in this line. Skip the version check
	if errVersion != nil {
		opt.Logger.Error("Migrate up get version error", zap.Error(err))
		return
	}

	if dirty {
		opt.Logger.Info("Dirty migration. Please clean up database")
	}

	msgLatestVersion := fmt.Sprintf("Latest version is %d", version)
	opt.Logger.Info(msgLatestVersion)
}

func migrateDown(opt *commons.Options, migrationDir string) {
	opt.Logger.Info("Migrating down database ...")
	db, err := opt.DB.DB()
	if err != nil {
		opt.Logger.Error("Error get SQL DB", zap.Error(err))
		return
	}
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		opt.Logger.Error("Driver error", zap.Error(err))
		return
	}

	migrateDatabase, err := migrate.NewWithDatabaseInstance(
		fmt.Sprintf("file://%s", migrationDir),
		"postgres", driver)
	if err != nil {
		opt.Logger.Error("Migrate error", zap.Error(err))
		return
	}

	err = migrateDatabase.Down()
	if err != nil {
		opt.Logger.Error("Migrate down error", zap.Error(err))
		return
	}

	opt.Logger.Info("Migration done ...")
}
