package authtypes

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
)

type OIDCSession struct {
	Issuer   string
	ClientID string
	OrgID    string
	Subject  string
	SID      string
	IssuedAt int64
}

func (s OIDCSession) Meta() map[string]string {
	return map[string]string{"authn": "oidc", "oidc_issuer": s.Issuer, "oidc_client": s.ClientID,
		"oidc_org": s.OrgID, "oidc_sub": s.Subject, "oidc_sid": s.SID, "oidc_iat": strconv.FormatInt(s.IssuedAt, 10)}
}

func OIDCSessionFromMeta(meta map[string]string) OIDCSession {
	iat, _ := strconv.ParseInt(meta["oidc_iat"], 10, 64)
	return OIDCSession{Issuer: meta["oidc_issuer"], ClientID: meta["oidc_client"], OrgID: meta["oidc_org"],
		Subject: meta["oidc_sub"], SID: meta["oidc_sid"], IssuedAt: iat}
}

func (s OIDCSession) RevocationKey(kind, value string) string {
	raw, _ := json.Marshal([]string{s.Issuer, s.ClientID, s.OrgID, kind, value})
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}
