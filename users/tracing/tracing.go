// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"context"

	"github.com/absmach/magistrala"
	mgclients "github.com/absmach/magistrala/pkg/clients"
	"github.com/absmach/magistrala/users"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var _ users.Service = (*tracingMiddleware)(nil)

// tracing has the service functions

type tracingMiddleware struct {
	tracer trace.Tracer
	svc    users.Service
}

// New returns a new group service with tracing capabilities.
func New(svc users.Service, tracer trace.Tracer) users.Service {
	return &tracingMiddleware{tracer, svc}
}

// RegisterUser traces the "RegisterUser" operation of the wrapped users.Service.
func (tm *tracingMiddleware) RegisterUser(ctx context.Context, token string, user users.User) (users.User, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_register_client", trace.WithAttributes(attribute.String("identity", user.Credentials.Identity)))
	defer span.End()

	return tm.svc.RegisterUser(ctx, token, user)
}

// IssueToken traces the "IssueToken" operation of the wrapped users.Service.
func (tm *tracingMiddleware) IssueToken(ctx context.Context, identity, secret, domainID string) (*magistrala.Token, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_issue_token", trace.WithAttributes(attribute.String("identity", identity)))
	defer span.End()

	return tm.svc.IssueToken(ctx, identity, secret, domainID)
}

// RefreshToken traces the "RefreshToken" operation of the wrapped users.Service.
func (tm *tracingMiddleware) RefreshToken(ctx context.Context, accessToken, domainID string) (*magistrala.Token, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_refresh_token", trace.WithAttributes(attribute.String("access_token", accessToken)))
	defer span.End()

	return tm.svc.RefreshToken(ctx, accessToken, domainID)
}

// ViewUser traces the "ViewUser" operation of the wrapped users.Service.
func (tm *tracingMiddleware) ViewUser(ctx context.Context, token, id string) (users.User, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_view_client", trace.WithAttributes(attribute.String("id", id)))
	defer span.End()

	return tm.svc.ViewUser(ctx, token, id)
}

// ListUsers traces the "ListUsers" operation of the wrapped users.Service.
func (tm *tracingMiddleware) ListUsers(ctx context.Context, token string, pm mgclients.Page) (users.UsersPage, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_list_clients", trace.WithAttributes(
		attribute.Int64("offset", int64(pm.Offset)),
		attribute.Int64("limit", int64(pm.Limit)),
		attribute.String("direction", pm.Dir),
		attribute.String("order", pm.Order),
	))

	defer span.End()

	return tm.svc.ListUsers(ctx, token, pm)
}

// SearchUsers traces the "SearchUsers" operation of the wrapped users.Service.
func (tm *tracingMiddleware) SearchUsers(ctx context.Context, token string, pm mgclients.Page) (users.UsersPage, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_search_clients", trace.WithAttributes(attribute.String("token", token)))
	defer span.End()

	return tm.svc.SearchUsers(ctx, token, pm)
}

// UpdateUser traces the "UpdateUser" operation of the wrapped users.Service.
func (tm *tracingMiddleware) UpdateUser(ctx context.Context, token string, usr users.User) (users.User, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_update_client_name_and_metadata", trace.WithAttributes(
		attribute.String("id", usr.ID),
		attribute.String("name", usr.Name),
	))
	defer span.End()

	return tm.svc.UpdateUser(ctx, token, usr)
}

// UpdateUserTags traces the "UpdateUserTags" operation of the wrapped users.Service.
func (tm *tracingMiddleware) UpdateUserTags(ctx context.Context, token string, usr users.User) (users.User, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_update_client_tags", trace.WithAttributes(
		attribute.String("id", usr.ID),
		attribute.StringSlice("tags", usr.Tags),
	))
	defer span.End()

	return tm.svc.UpdateUserTags(ctx, token, usr)
}

// UpdateUserIdentity traces the "UpdateUserIdentity" operation of the wrapped users.Service.
func (tm *tracingMiddleware) UpdateUserIdentity(ctx context.Context, token, id, identity string) (users.User, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_update_client_identity", trace.WithAttributes(
		attribute.String("id", id),
		attribute.String("identity", identity),
	))
	defer span.End()

	return tm.svc.UpdateUserIdentity(ctx, token, id, identity)
}

// UpdateUserSecret traces the "UpdateUserSecret" operation of the wrapped users.Service.
func (tm *tracingMiddleware) UpdateUserSecret(ctx context.Context, token, oldSecret, newSecret string) (users.User, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_update_client_secret")
	defer span.End()

	return tm.svc.UpdateUserSecret(ctx, token, oldSecret, newSecret)
}

// UpdateUserFullName traces the "UpdateUserFullName" operation of the wrapped users.Service.
func (tm *tracingMiddleware) UpdateUserNames(ctx context.Context, token string, user users.User) (users.User, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_update_client_names", trace.WithAttributes(
		attribute.String("id", user.ID),
		attribute.String("name", user.Name),
		attribute.String("fisrt_name", user.FirstName),
		attribute.String("last_name", user.LastName),
		attribute.String("user_name", user.UserName),
		attribute.String("name", user.Name),
	))
	defer span.End()

	return tm.svc.UpdateUserNames(ctx, token, user)
}

// UpdateProfilePicture traces the "UpdateProfilePicture" operation of the wrapped users.Service.
func (tm *tracingMiddleware) UpdateProfilePicture(ctx context.Context, token string, usr users.User) (users.User, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_update_profile_picture", trace.WithAttributes(attribute.String("id", usr.ID)))
	defer span.End()

	return tm.svc.UpdateProfilePicture(ctx, token, usr)
}

// GenerateResetToken traces the "GenerateResetToken" operation of the wrapped users.Service.
func (tm *tracingMiddleware) GenerateResetToken(ctx context.Context, email, host string) error {
	ctx, span := tm.tracer.Start(ctx, "svc_generate_reset_token", trace.WithAttributes(
		attribute.String("email", email),
		attribute.String("host", host),
	))
	defer span.End()

	return tm.svc.GenerateResetToken(ctx, email, host)
}

// ResetSecret traces the "ResetSecret" operation of the wrapped users.Service.
func (tm *tracingMiddleware) ResetSecret(ctx context.Context, token, secret string) error {
	ctx, span := tm.tracer.Start(ctx, "svc_reset_secret")
	defer span.End()

	return tm.svc.ResetSecret(ctx, token, secret)
}

// SendPasswordReset traces the "SendPasswordReset" operation of the wrapped users.Service.
func (tm *tracingMiddleware) SendPasswordReset(ctx context.Context, host, email, user, token string) error {
	ctx, span := tm.tracer.Start(ctx, "svc_send_password_reset", trace.WithAttributes(
		attribute.String("email", email),
		attribute.String("user", user),
	))
	defer span.End()

	return tm.svc.SendPasswordReset(ctx, host, email, user, token)
}

// ViewProfile traces the "ViewProfile" operation of the wrapped users.Service.
func (tm *tracingMiddleware) ViewProfile(ctx context.Context, token string) (users.User, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_view_profile")
	defer span.End()

	return tm.svc.ViewProfile(ctx, token)
}

// viewUserByUserName traces the "ViewUserByUserName" operation of the wrapped users.Service.
func (tm *tracingMiddleware) ViewUserByUserName(ctx context.Context, token, userName string) (users.User, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_view_client_by_username", trace.WithAttributes(attribute.String("username", userName)))
	defer span.End()

	return tm.svc.ViewUserByUserName(ctx, token, userName)
}

// UpdateUserRole traces the "UpdateUserRole" operation of the wrapped users.Service.
func (tm *tracingMiddleware) UpdateUserRole(ctx context.Context, token string, usr users.User) (users.User, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_update_client_role", trace.WithAttributes(
		attribute.String("id", usr.ID),
		attribute.StringSlice("tags", usr.Tags),
	))
	defer span.End()

	return tm.svc.UpdateUserRole(ctx, token, usr)
}

// EnableUser traces the "EnableUser" operation of the wrapped users.Service.
func (tm *tracingMiddleware) EnableUser(ctx context.Context, token, id string) (users.User, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_enable_client", trace.WithAttributes(attribute.String("id", id)))
	defer span.End()

	return tm.svc.EnableUser(ctx, token, id)
}

// DisableUser traces the "DisableUser" operation of the wrapped users.Service.
func (tm *tracingMiddleware) DisableUser(ctx context.Context, token, id string) (users.User, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_disable_client", trace.WithAttributes(attribute.String("id", id)))
	defer span.End()

	return tm.svc.DisableUser(ctx, token, id)
}

// ListMembers traces the "ListMembers" operation of the wrapped users.Service.
func (tm *tracingMiddleware) ListMembers(ctx context.Context, token, objectKind, objectID string, pm mgclients.Page) (users.MembersPage, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_list_members", trace.WithAttributes(attribute.String("object_kind", objectKind)), trace.WithAttributes(attribute.String("object_id", objectID)))
	defer span.End()

	return tm.svc.ListMembers(ctx, token, objectKind, objectID, pm)
}

// Identify traces the "Identify" operation of the wrapped users.Service.
func (tm *tracingMiddleware) Identify(ctx context.Context, token string) (string, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_identify", trace.WithAttributes(attribute.String("token", token)))
	defer span.End()

	return tm.svc.Identify(ctx, token)
}

// OAuthCallback traces the "OAuthCallback" operation of the wrapped users.Service.
func (tm *tracingMiddleware) OAuthCallback(ctx context.Context, user users.User) (*magistrala.Token, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_oauth_callback", trace.WithAttributes(
		attribute.String("client_id", user.ID),
	))
	defer span.End()

	return tm.svc.OAuthCallback(ctx, user)
}

// DeleteUser traces the "DeleteUser" operation of the wrapped users.Service.
func (tm *tracingMiddleware) DeleteUser(ctx context.Context, token, id string) error {
	ctx, span := tm.tracer.Start(ctx, "svc_delete_client", trace.WithAttributes(attribute.String("id", id)))
	defer span.End()

	return tm.svc.DeleteUser(ctx, token, id)
}
