package credbridge

// OPDiscoveryMetadata is the JSON body the OP returns from
// /.well-known/openid-configuration. It embeds the standard OIDC/OAuth
// authorization-server metadata members the bridge cares about and adds
// the two members registered in Section 8.2.
type OPDiscoveryMetadata struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserInfoEndpoint                 string   `json:"userinfo_endpoint,omitempty"`
	JWKSURI                          string   `json:"jwks_uri,omitempty"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported,omitempty"`
	ClaimsSupported                  []string `json:"claims_supported,omitempty"`

	// CredentialPresentationsSupported publishes the OP's scope-to-
	// credential-type mapping (Section 5.2).
	CredentialPresentationsSupported map[string]OPDiscoveryCredentialType `json:"credential_presentations_supported"`

	// DCQLQuerySupported is the flag from Section 5.2. Omitted when
	// false so RPs treat its absence as false per Section 5.2.
	DCQLQuerySupported bool `json:"dcql_query_supported,omitempty"`
}

// OPDiscoveryCredentialType is one entry inside
// credential_presentations_supported.
type OPDiscoveryCredentialType struct {
	Format       string     `json:"format"`
	Type         []string   `json:"type"`
	Claims       [][]string `json:"claims,omitempty"`
	SubjectClaim []string   `json:"subject_claim,omitempty"`
}

// Metadata returns the discovery document for this OP.
func (o *OP) Metadata() OPDiscoveryMetadata {
	credTypes := make(map[string]OPDiscoveryCredentialType, len(o.cfg.CredentialPresentations))
	scopes := make([]string, 0, len(o.cfg.CredentialPresentations)+1)
	scopes = append(scopes, "openid")
	for scope, cfg := range o.cfg.CredentialPresentations {
		credTypes[scope] = OPDiscoveryCredentialType(cfg)
		scopes = append(scopes, scope)
	}
	return OPDiscoveryMetadata{
		Issuer:                           o.cfg.Issuer,
		AuthorizationEndpoint:            o.cfg.AuthorizationEndpoint,
		TokenEndpoint:                    o.cfg.TokenEndpoint,
		UserInfoEndpoint:                 o.cfg.UserInfoEndpoint,
		JWKSURI:                          o.cfg.JWKSURI,
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"pairwise"},
		IDTokenSigningAlgValuesSupported: []string{o.cfg.Signer.Algorithm()},
		ScopesSupported:                  scopes,
		ClaimsSupported:                  []string{"sub", PresentedCredentialSetsClaim},
		CredentialPresentationsSupported: credTypes,
		DCQLQuerySupported:               o.cfg.DCQLQuerySupported,
	}
}
