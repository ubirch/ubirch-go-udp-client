package vars

const (
	PostgreSql          string = "postgres"
	PostgreSqlPort      int    = 5432
	PostgreSqlTableName string = "identity"
	MigrateArg          string = "migrate"

	UUIDKey      = "uuid"
	OperationKey = "operation"
	VerifyPath   = "verify"
	HashEndpoint = "hash"

	BinType  = "application/octet-stream"
	TextType = "text/plain"
	JSONType = "application/json"

	HexEncoding = "hex"

	HashLen = 32
)
