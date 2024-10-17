package email

type EmailRequest struct {
	EmailTo    []string `json:"email_to"`
	Subject    string   `json:"subject"`
	Message    string   `json:"message"`
	Attachment string   `json:"attachment"` //path of file attachment
}
