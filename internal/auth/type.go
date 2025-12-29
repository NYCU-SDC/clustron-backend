package auth

type ProviderType string

func (p ProviderType) String() string {
	return string(p)
}

const (
	ProviderTypeGoogle ProviderType = "GOOGLE"
	ProviderTypeNYCU   ProviderType = "NYCU"
	ProviderTypeGithub ProviderType = "GITHUB"
)

var ProviderTypesMap = map[string]ProviderType{
	"google": ProviderTypeGoogle,
	"nycu":   ProviderTypeNYCU,
	"github": ProviderTypeGithub,
}
