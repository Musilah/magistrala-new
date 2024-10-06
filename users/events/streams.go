// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"context"

	"github.com/absmach/magistrala"
	mgclients "github.com/absmach/magistrala/pkg/clients"
	"github.com/absmach/magistrala/pkg/events"
	"github.com/absmach/magistrala/pkg/events/store"
	"github.com/absmach/magistrala/users"
)

const streamID = "magistrala.users"

var _ users.Service = (*eventStore)(nil)

type eventStore struct {
	events.Publisher
	svc users.Service
}

// NewEventStoreMiddleware returns wrapper around users service that sends
// events to event store.
func NewEventStoreMiddleware(ctx context.Context, svc users.Service, url string) (users.Service, error) {
	publisher, err := store.NewPublisher(ctx, url, streamID)
	if err != nil {
		return nil, err
	}

	return &eventStore{
		svc:       svc,
		Publisher: publisher,
	}, nil
}

func (es *eventStore) RegisterUser(ctx context.Context, token string, user users.User) (users.User, error) {
	user, err := es.svc.RegisterUser(ctx, token, user)
	if err != nil {
		return user, err
	}

	event := createUserEvent{
		user,
	}

	if err := es.Publish(ctx, event); err != nil {
		return user, err
	}

	return user, nil
}

func (es *eventStore) UpdateUser(ctx context.Context, token string, user users.User) (users.User, error) {
	user, err := es.svc.UpdateUser(ctx, token, user)
	if err != nil {
		return user, err
	}

	return es.update(ctx, "", user)
}

func (es *eventStore) UpdateUserRole(ctx context.Context, token string, user users.User) (users.User, error) {
	user, err := es.svc.UpdateUserRole(ctx, token, user)
	if err != nil {
		return user, err
	}

	return es.update(ctx, "role", user)
}

func (es *eventStore) UpdateUserTags(ctx context.Context, token string, user users.User) (users.User, error) {
	user, err := es.svc.UpdateUserTags(ctx, token, user)
	if err != nil {
		return user, err
	}

	return es.update(ctx, "tags", user)
}

func (es *eventStore) UpdateUserSecret(ctx context.Context, token, oldSecret, newSecret string) (users.User, error) {
	user, err := es.svc.UpdateUserSecret(ctx, token, oldSecret, newSecret)
	if err != nil {
		return user, err
	}

	return es.update(ctx, "secret", user)
}

func (es *eventStore) UpdateUserNames(ctx context.Context, token string, user users.User) (users.User, error) {
	user, err := es.svc.UpdateUserNames(ctx, token, user)
	if err != nil {
		return user, err
	}

	event := updateUserNamesEvent{
		user,
	}

	if err := es.Publish(ctx, event); err != nil {
		return user, err
	}

	return user, nil
}

func (es *eventStore) UpdateProfilePicture(ctx context.Context, token string, user users.User) (users.User, error) {
	user, err := es.svc.UpdateProfilePicture(ctx, token, user)
	if err != nil {
		return user, err
	}

	event := updateProfilePictureEvent{
		user,
	}

	if err := es.Publish(ctx, event); err != nil {
		return user, err
	}

	return user, nil
}

func (es *eventStore) UpdateUserIdentity(ctx context.Context, token, id, identity string) (users.User, error) {
	user, err := es.svc.UpdateUserIdentity(ctx, token, id, identity)
	if err != nil {
		return user, err
	}

	return es.update(ctx, "identity", user)
}

func (es *eventStore) update(ctx context.Context, operation string, user users.User) (users.User, error) {
	event := updateUserEvent{
		user, operation,
	}

	if err := es.Publish(ctx, event); err != nil {
		return user, err
	}

	return user, nil
}

func (es *eventStore) ViewUser(ctx context.Context, token, id string) (users.User, error) {
	user, err := es.svc.ViewUser(ctx, token, id)
	if err != nil {
		return user, err
	}

	event := viewUserEvent{
		user,
	}

	if err := es.Publish(ctx, event); err != nil {
		return user, err
	}

	return user, nil
}

func (es *eventStore) ViewProfile(ctx context.Context, token string) (users.User, error) {
	user, err := es.svc.ViewProfile(ctx, token)
	if err != nil {
		return user, err
	}

	event := viewProfileEvent{
		user,
	}

	if err := es.Publish(ctx, event); err != nil {
		return user, err
	}

	return user, nil
}

func (es *eventStore) ViewUserByUserName(ctx context.Context, token, userName string) (users.User, error) {
	user, err := es.svc.ViewUserByUserName(ctx, token, userName)
	if err != nil {
		return user, err
	}

	event := viewUserByUserNameEvent{
		user,
	}

	if err := es.Publish(ctx, event); err != nil {
		return user, err
	}

	return user, nil
}

func (es *eventStore) ListUsers(ctx context.Context, token string, pm mgclients.Page) (users.UsersPage, error) {
	cp, err := es.svc.ListUsers(ctx, token, pm)
	if err != nil {
		return cp, err
	}
	event := listUserEvent{
		pm,
	}

	if err := es.Publish(ctx, event); err != nil {
		return cp, err
	}

	return cp, nil
}

func (es *eventStore) SearchUsers(ctx context.Context, token string, pm mgclients.Page) (users.UsersPage, error) {
	cp, err := es.svc.SearchUsers(ctx, token, pm)
	if err != nil {
		return cp, err
	}
	event := searchUserEvent{
		pm,
	}

	if err := es.Publish(ctx, event); err != nil {
		return cp, err
	}

	return cp, nil
}

func (es *eventStore) ListMembers(ctx context.Context, token, objectKind, objectID string, pm mgclients.Page) (users.MembersPage, error) {
	mp, err := es.svc.ListMembers(ctx, token, objectKind, objectID, pm)
	if err != nil {
		return mp, err
	}
	event := listUserByGroupEvent{
		pm, objectKind, objectID,
	}

	if err := es.Publish(ctx, event); err != nil {
		return mp, err
	}

	return mp, nil
}

func (es *eventStore) EnableUser(ctx context.Context, token, id string) (users.User, error) {
	user, err := es.svc.EnableUser(ctx, token, id)
	if err != nil {
		return user, err
	}

	return es.delete(ctx, user)
}

func (es *eventStore) DisableUser(ctx context.Context, token, id string) (users.User, error) {
	user, err := es.svc.DisableUser(ctx, token, id)
	if err != nil {
		return user, err
	}

	return es.delete(ctx, user)
}

func (es *eventStore) delete(ctx context.Context, user users.User) (users.User, error) {
	event := removeUserEvent{
		id:        user.ID,
		updatedAt: user.UpdatedAt,
		updatedBy: user.UpdatedBy,
		status:    user.Status.String(),
	}

	if err := es.Publish(ctx, event); err != nil {
		return user, err
	}

	return user, nil
}

func (es *eventStore) Identify(ctx context.Context, token string) (string, error) {
	userID, err := es.svc.Identify(ctx, token)
	if err != nil {
		return userID, err
	}

	event := identifyUserEvent{
		userID: userID,
	}

	if err := es.Publish(ctx, event); err != nil {
		return userID, err
	}

	return userID, nil
}

func (es *eventStore) GenerateResetToken(ctx context.Context, email, host string) error {
	if err := es.svc.GenerateResetToken(ctx, email, host); err != nil {
		return err
	}

	event := generateResetTokenEvent{
		email: email,
		host:  host,
	}

	return es.Publish(ctx, event)
}

func (es *eventStore) IssueToken(ctx context.Context, identity, secret, domainID string) (*magistrala.Token, error) {
	token, err := es.svc.IssueToken(ctx, identity, secret, domainID)
	if err != nil {
		return token, err
	}

	event := issueTokenEvent{
		identity: identity,
		domainID: domainID,
	}

	if err := es.Publish(ctx, event); err != nil {
		return token, err
	}

	return token, nil
}

func (es *eventStore) RefreshToken(ctx context.Context, refreshToken, domainID string) (*magistrala.Token, error) {
	token, err := es.svc.RefreshToken(ctx, refreshToken, domainID)
	if err != nil {
		return token, err
	}

	event := refreshTokenEvent{domainID: domainID}

	if err := es.Publish(ctx, event); err != nil {
		return token, err
	}

	return token, nil
}

func (es *eventStore) ResetSecret(ctx context.Context, resetToken, secret string) error {
	if err := es.svc.ResetSecret(ctx, resetToken, secret); err != nil {
		return err
	}

	event := resetSecretEvent{}

	return es.Publish(ctx, event)
}

func (es *eventStore) SendPasswordReset(ctx context.Context, host, email, user, token string) error {
	if err := es.svc.SendPasswordReset(ctx, host, email, user, token); err != nil {
		return err
	}

	event := sendPasswordResetEvent{
		host:  host,
		email: email,
		user:  user,
	}

	return es.Publish(ctx, event)
}

func (es *eventStore) OAuthCallback(ctx context.Context, user users.User) (*magistrala.Token, error) {
	token, err := es.svc.OAuthCallback(ctx, user)
	if err != nil {
		return token, err
	}

	event := oauthCallbackEvent{
		userID: user.ID,
	}

	if err := es.Publish(ctx, event); err != nil {
		return token, err
	}

	return token, nil
}

func (es *eventStore) DeleteUser(ctx context.Context, token, id string) error {
	if err := es.svc.DeleteUser(ctx, token, id); err != nil {
		return err
	}

	event := deleteUserEvent{
		id: id,
	}

	return es.Publish(ctx, event)
}
