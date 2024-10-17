package config

type ConfigObject struct {
	AppHost           string `mapstructure:"APP_HOST"`
	AppPort           int    `mapstructure:"APP_PORT"`
	AppName           string `mapstructure:"APP_NAME"`
	AppLogLevel       string `mapstructure:"APP_LOG_LEVEL"`
	AppMigrationPath  string `mapstructure:"APP_MIGRATION_PATH"`
	DumpRequest       string `mapstructure:"SHOW_REQUEST"`
	AllowOrigins      string `mapstructure:"ALLOW_ORIGINS"`
	LoginURL          string `mapstructure:"LOGIN_URL"`
	ForgotPasswordURL string `mapstructure:"FORGOT_PASSWORD_URL"`
	//	DB
	DBHost        string `mapstructure:"DB_HOST"`
	DBPort        int    `mapstructure:"DB_PORT"`
	DBName        string `mapstructure:"DB_NAME"`
	DBUsername    string `mapstructure:"DB_USERNAME"`
	DBPassword    string `mapstructure:"DB_PASSWORD"`
	DBMaxPoolSize int    `mapstructure:"DB_MAX_POOL_SIZE"`
	DBBatchSize   int    `mapstructure:"DB_BATCH_SIZE"`
	//	Redis
	RedisHost                  string `mapstructure:"REDIS_HOST"`
	RedisPort                  int    `mapstructure:"REDIS_PORT"`
	RedisDialConnectTimeout    string `mapstructure:"REDIS_DIAL_CONNECT_TIMEOUT"`
	RedisReadTimeout           string `mapstructure:"REDIS_READ_TIMEOUT"`
	RedisWriteTimeout          string `mapstructure:"REDIS_WRITE_TIMEOUT"`
	RedisIdleTimeout           string `mapstructure:"REDIS_IDLE_TIMEOUT"`
	RedisConnLifetimeMax       string `mapstructure:"REDIS_CONN_LIFETIME_MAX"`
	RedisConnIdleMax           int    `mapstructure:"REDIS_CONN_IDLE_MAX"`
	RedisConnActiveMax         int    `mapstructure:"REDIS_CONN_ACTIVE_MAX"`
	RedisIsWait                bool   `mapstructure:"REDIS_IS_WAIT"`
	RedisNamespace             string `mapstructure:"REDIS_NAMESPACE"`
	RedisPassword              string `mapstructure:"REDIS_PASSWORD"`
	RedisLockerTries           int    `mapstructure:"REDIS_LOCKER_TRIES"`
	RedisLockerTriesRetryDelay string `mapstructure:"REDIS_LOCKER_TRIES_RETRY_DELAY"`
	RedisLockerExpiry          string `mapstructure:"REDIS_LOCKER_EXPIRY"`
	//	Casbin
	CasbinModelPath            string `mapstructure:"CASBIN_MODEL_PATH"`
	CasbinPolicyReloadDuration string `mapstructure:"CASBIN_POLICY_RELOAD_DURATION"`
	CasbinAutoMigrateTable     string `mapstructure:"CASBIN_AUTO_MIGRATE_TABLE"`
	//	JWT
	JwtAccessSecret  string `mapstructure:"JWT_ACCESS_SECRET"`
	JwtRefreshSecret string `mapstructure:"JWT_REFRESH_SECRET"`
	JwtAccessTtl     string `mapstructure:"JWT_ACCESS_TTL"`
	JwtRefreshTtl    string `mapstructure:"JWT_REFRESH_TTL"`
	//	Email Setting
	MailSmtpHost     string `mapstructure:"MAIL_SMTP_HOST"`
	MailSmtpPort     int    `mapstructure:"MAIL_SMTP_PORT"`
	MailSenderName   string `mapstructure:"MAIL_SENDER_NAME"`
	MailAuth         string `mapstructure:"MAIL_AUTH"`
	MailAuthPassword string `mapstructure:"MAIL_AUTH_PASSWORD"`
	MailAlias        string `mapstructure:"MAIL_ALIAS"`
	// Minio S3
	MinioEndpoint        string `mapstructure:"MINIO_ENDPOINT"`
	MinioAccessKeyID     string `mapstructure:"MINIO_ACCESS_KEY"`
	MinioSecretAccessKey string `mapstructure:"MINIO_SECRET"`
	MinioUseSSL          bool   `mapstructure:"MINIO_USE_SSL"`
	// MongoDB
	MongoDBHost     string `mapstructure:"MONGO_DB_HOST"`
	MongoDBPort     int    `mapstructure:"MONGO_DB_PORT"`
	MongoDBName     string `mapstructure:"MONGO_DB_NAME"`
	MongoDBUsername string `mapstructure:"MONGO_DB_USERNAME"`
	MongoDBPassword string `mapstructure:"MONGO_DB_PASSWORD"`
}
