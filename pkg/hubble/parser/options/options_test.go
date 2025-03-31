// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package options

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/sirupsen/logrus"
)

var log *logrus.Logger

func init() {
	log = logrus.New()
	log.Formatter = &logrus.TextFormatter{
		DisableTimestamp: true,
	}
}

func TestRedact(t *testing.T) {
	want := "level=info msg=\"configured Hubble with redact\" options=\"{Enabled:true RedactHTTPQuery:false RedactHTTPUserInfo:false RedactKafkaAPIKey:false RedactHttpHeaders:{Allow:map[] Deny:map[]}}\"\n"
	var buf bytes.Buffer

	log.SetOutput(&buf)
	opt := WithRedact(log, false, false, false, nil, nil)
	opt(&Options{
		HubbleRedactSettings: HubbleRedactSettings{
			Enabled:            false,
			RedactHTTPQuery:    false,
			RedactHTTPUserInfo: false,
			RedactKafkaAPIKey:  false,
			RedactHttpHeaders: HttpHeadersList{
				Allow: map[string]struct{}{},
				Deny:  map[string]struct{}{"tracecontent": {}},
			},
		},
	})
	assert.Equal(t, want, buf.String())
}

func TestEnableNetworkPolicyCorrelation(t *testing.T) {
	want := "level=info msg=\"configured Hubble with network policy correlation\" options=true\n"
	var buf bytes.Buffer
	log.SetOutput(&buf)
	opt := WithNetworkPolicyCorrelation(log, true)
	opt(&Options{
		EnableNetworkPolicyCorrelation: true,
	})
	assert.Equal(t, want, buf.String())
}
