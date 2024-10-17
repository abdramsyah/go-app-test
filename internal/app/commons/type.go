package commons

type PaginationConfig struct {
	Offset   int
	PageSize int
}

type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	AccessUuid   string
	RefreshUuid  string
	AtExpires    int64
	RtExpires    int64
}

type AuthCacheValue struct {
	UserID uint `json:"user_id"`
}

type AuthUUIDCacheValue struct {
	UUID string `json:"uuid"`
}

type PaginateResponse struct {
	List  interface{} `json:"list"`
	Count int64       `json:"count"`
}
