package serviceaccounttypes

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOIDCBindingValidation(t *testing.T) {
	require.Error(t, (*PostableOIDCBinding)(nil).Validate())
	for _, value := range []string{"", " ", "client\n", "sub\x00ject", strings.Repeat("a", 256)} {
		require.Error(t, (&PostableOIDCBinding{ClientID: value, Subject: "subject"}).Validate())
		require.Error(t, (&PostableOIDCBinding{ClientID: "client", Subject: value}).Validate())
	}
	require.NoError(t, (&PostableOIDCBinding{ClientID: strings.Repeat("a", 255), Subject: "uuid-subject"}).Validate())
}
