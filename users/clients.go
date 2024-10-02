// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package users

import (
	"context"

	"github.com/absmach/magistrala"
	"github.com/absmach/magistrala/pkg/clients"
)

// Service specifies an API that must be fullfiled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
//
//go:generate mockery --name Service --output=./mocks --filename service.go --quiet --note "Copyright (c) Abstract Machines"
type Service interface {
	// RegisterUser creates new user. In case of the failed registration, a
	// non-nil error value is returned.
	RegisterUser(ctx context.Context, token string, user User) (User, error)

	// ViewUser retrieves user info for a given user ID and an authorized token.
	ViewUser(ctx context.Context, token, id string) (User, error)

	// ViewProfile retrieves user info for a given token.
	ViewProfile(ctx context.Context, token string) (User, error)

	// ViewUserByUserName retrieves user info for a given user name.
	ViewUserByUserName(ctx context.Context, token, userName string) (User, error)

	// ListUsers retrieves users list for a valid auth token.
	ListUsers(ctx context.Context, token string, pm clients.Page) (UsersPage, error)

	// ListMembers retrieves everything that is assigned to a group identified by objectID.
	ListMembers(ctx context.Context, token, objectKind, objectID string, pm clients.Page) (MembersPage, error)

	// SearchUsers searches for users with provided filters for a valid auth token.
	SearchUsers(ctx context.Context, token string, pm clients.Page) (UsersPage, error)

	// UpdateUser updates the user's name and metadata.
	UpdateUser(ctx context.Context, token string, user User) (User, error)

	// UpdateUserTags updates the user's tags.
	UpdateUserTags(ctx context.Context, token string, user User) (User, error)

	// UpdateUserIdentity updates the user's identity.
	UpdateUserIdentity(ctx context.Context, token, id, identity string) (User, error)

	// GenerateResetToken email where mail will be sent.
	// host is used for generating reset link.
	GenerateResetToken(ctx context.Context, email, host string) error

	// UpdateUserSecret updates the user's secret.
	UpdateUserSecret(ctx context.Context, token, oldSecret, newSecret string) (User, error)

	// UpdateUserFullName updates the user's full name.
	UpdateUserFullName(ctx context.Context, token, id, fullName string) (User, error)

	// ResetSecret change users secret in reset flow.
	// token can be authentication token or secret reset token.
	ResetSecret(ctx context.Context, resetToken, secret string) error

	// SendPasswordReset sends reset password link to email.
	SendPasswordReset(ctx context.Context, host, email, user, token string) error

	// UpdateUserRole updates the user's Role.
	UpdateUserRole(ctx context.Context, token string, user User) (User, error)

	// EnableUser logically enableds the user identified with the provided ID.
	EnableUser(ctx context.Context, token, id string) (User, error)

	// DisableUser logically disables the user identified with the provided ID.
	DisableUser(ctx context.Context, token, id string) (User, error)

	// DeleteUser deletes user with given ID.
	DeleteUser(ctx context.Context, token, id string) error

	// Identify returns the user id from the given token.
	Identify(ctx context.Context, tkn string) (string, error)

	// IssueToken issues a new access and refresh token.
	IssueToken(ctx context.Context, identity, secret, domainID string) (*magistrala.Token, error)

	// RefreshToken refreshes expired access tokens.
	// After an access token expires, the refresh token is used to get
	// a new pair of access and refresh tokens.
	RefreshToken(ctx context.Context, accessToken, domainID string) (*magistrala.Token, error)

	// OAuthCallback handles the callback from any supported OAuth provider.
	// It processes the OAuth tokens and either signs in or signs up the user based on the provided state.
	OAuthCallback(ctx context.Context, user User) (*magistrala.Token, error)
}
