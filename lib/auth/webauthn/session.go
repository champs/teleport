/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package webauthn

import (
	"encoding/base64"

	"github.com/gravitational/trace"

	wan "github.com/duo-labs/webauthn/webauthn"
	wantypes "github.com/gravitational/teleport/api/types/webauthn"
)

func sessionToPB(sd *wan.SessionData) (*wantypes.SessionData, error) {
	rawChallenge, err := base64.RawURLEncoding.DecodeString(sd.Challenge)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &wantypes.SessionData{
		Challenge:        rawChallenge,
		UserId:           sd.UserID,
		AllowCredentials: sd.AllowedCredentialIDs,
	}, nil
}

func sessionFromPB(sd *wantypes.SessionData) *wan.SessionData {
	return &wan.SessionData{
		Challenge:            base64.RawURLEncoding.EncodeToString(sd.Challenge),
		UserID:               sd.UserId,
		AllowedCredentialIDs: sd.AllowCredentials,
	}
}
