package dto

type RoleEmbed struct {
	ID       uint   `json:"id"`
	Name     string `json:"name"`
	RoleType string `json:"role_type"`
}

type RoleFilter struct {
	Name *string `query:"name"`
}
