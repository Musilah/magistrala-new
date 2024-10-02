// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"strings"
	"testing"

	"github.com/absmach/magistrala/internal/api"
	"github.com/absmach/magistrala/internal/testsutil"
	"github.com/absmach/magistrala/pkg/apiutil"
	"github.com/absmach/magistrala/users"
	"github.com/stretchr/testify/assert"
)

const (
	valid   = "valid"
	invalid = "invalid"
	secret  = "QJg58*aMan7j"
	name    = "user"
)

var validID = testsutil.GenerateUUID(&testing.T{})

func TestCreateUserReqValidate(t *testing.T) {
	cases := []struct {
		desc string
		req  createUserReq
		err  error
	}{
		{
			desc: "valid request",
			req: createUserReq{
				token: valid,
				user: users.User{
					ID:   validID,
					Name: valid,
					Credentials: users.Credentials{
						Identity: "example@example.com",
						Secret:   secret,
					},
				},
			},
			err: nil,
		},
		{
			desc: "empty token",
			req: createUserReq{
				token: "",
				user: users.User{
					ID:   validID,
					Name: valid,
					Credentials: users.Credentials{
						Identity: "example@example.com",
						Secret:   secret,
					},
				},
			},
		},
		{
			desc: "name too long",
			req: createUserReq{
				token: valid,
				user: users.User{
					ID:   validID,
					Name: strings.Repeat("a", api.MaxNameSize+1),
				},
			},
			err: apiutil.ErrNameSize,
		},
		{
			desc: "missing identity in request",
			req: createUserReq{
				token: valid,
				user: users.User{
					ID:   validID,
					Name: valid,
					Credentials: users.Credentials{
						Secret: valid,
					},
				},
			},
			err: apiutil.ErrMissingIdentity,
		},
		{
			desc: "missing secret in request",
			req: createUserReq{
				token: valid,
				user: users.User{
					ID:   validID,
					Name: valid,
					Credentials: users.Credentials{
						Identity: "example@example.com",
					},
				},
			},
			err: apiutil.ErrMissingPass,
		},
		{
			desc: "invalid secret in request",
			req: createUserReq{
				token: valid,
				user: users.User{
					ID:   validID,
					Name: valid,
					Credentials: users.Credentials{
						Identity: "example@example.com",
						Secret:   "invalid",
					},
				},
			},
			err: apiutil.ErrPasswordFormat,
		},
	}
	for _, tc := range cases {
		err := tc.req.validate()
		assert.Equal(t, tc.err, err)
	}
}

func TestViewUserReqValidate(t *testing.T) {
	cases := []struct {
		desc string
		req  viewUserReq
		err  error
	}{
		{
			desc: "valid request",
			req: viewUserReq{
				token: valid,
				id:    validID,
			},
			err: nil,
		},
		{
			desc: "empty token",
			req: viewUserReq{
				token: "",
				id:    validID,
			},
			err: apiutil.ErrBearerToken,
		},
		{
			desc: "empty id",
			req: viewUserReq{
				token: valid,
				id:    "",
			},
			err: apiutil.ErrMissingID,
		},
	}
	for _, c := range cases {
		err := c.req.validate()
		assert.Equal(t, c.err, err, "%s: expected %s got %s\n", c.desc, c.err, err)
	}
}

func TestViewProfileReqValidate(t *testing.T) {
	cases := []struct {
		desc string
		req  viewProfileReq
		err  error
	}{
		{
			desc: "valid request",
			req: viewProfileReq{
				token: valid,
			},
			err: nil,
		},
		{
			desc: "empty token",
			req: viewProfileReq{
				token: "",
			},
			err: apiutil.ErrBearerToken,
		},
	}
	for _, c := range cases {
		err := c.req.validate()
		assert.Equal(t, c.err, err)
	}
}

func TestViewUserByUserNameReqValidate(t *testing.T) {
	cases := []struct {
		desc string
		req  viewUserByUserNameReq
		err  error
	}{
		{
			desc: "valid request",
			req: viewUserByUserNameReq{
				token:    valid,
				userName: name,
			},
			err: nil,
		},
		{
			desc: "empty token",
			req: viewUserByUserNameReq{
				token:    "",
				userName: name,
			},
			err: apiutil.ErrBearerToken,
		},
		{
			desc: "empty username",
			req: viewUserByUserNameReq{
				token:    valid,
				userName: "",
			},
			err: apiutil.ErrMissingUserName,
		},
	}
	for _, c := range cases {
		err := c.req.validate()
		assert.Equal(t, c.err, err)
	}
}

func TestUpdateUserFullNameReqValidate(t *testing.T) {
	cases := []struct {
		desc string
		req  updateUserFullNameReq
		err  error
	}{
		{
			desc: "valid request",
			req: updateUserFullNameReq{
				token:    valid,
				id:       validID,
				FullName: valid,
			},
			err: nil,
		},
		{
			desc: "empty token",
			req: updateUserFullNameReq{
				token:    "",
				id:       validID,
				FullName: valid,
			},
			err: apiutil.ErrBearerToken,
		},
		{
			desc: "empty id",
			req: updateUserFullNameReq{
				token:    valid,
				id:       "",
				FullName: valid,
			},
			err: apiutil.ErrMissingID,
		},
		{
			desc: "empty full name",
			req: updateUserFullNameReq{
				token:    valid,
				id:       validID,
				FullName: "",
			},
			err: apiutil.ErrMissingFullName,
		},
	}
	for _, c := range cases {
		err := c.req.validate()
		assert.Equal(t, c.err, err)
	}
}

func TestListUsersReqValidate(t *testing.T) {
	cases := []struct {
		desc string
		req  listUsersReq
		err  error
	}{
		{
			desc: "valid request",
			req: listUsersReq{
				token: valid,
				limit: 10,
			},
			err: nil,
		},
		{
			desc: "empty token",
			req: listUsersReq{
				token: "",
				limit: 10,
			},
			err: apiutil.ErrBearerToken,
		},
		{
			desc: "limit too big",
			req: listUsersReq{
				token: valid,
				limit: api.MaxLimitSize + 1,
			},
			err: apiutil.ErrLimitSize,
		},
		{
			desc: "limit too small",
			req: listUsersReq{
				token: valid,
				limit: 0,
			},
			err: apiutil.ErrLimitSize,
		},
		{
			desc: "invalid direction",
			req: listUsersReq{
				token: valid,
				limit: 10,
				dir:   "invalid",
			},
			err: apiutil.ErrInvalidDirection,
		},
	}
	for _, c := range cases {
		err := c.req.validate()
		assert.Equal(t, c.err, err, "%s: expected %s got %s\n", c.desc, c.err, err)
	}
}

func TestSearchUsersReqValidate(t *testing.T) {
	cases := []struct {
		desc string
		req  searchUsersReq
		err  error
	}{
		{
			desc: "valid request",
			req: searchUsersReq{
				token: valid,
				Name:  name,
			},
			err: nil,
		},
		{
			desc: "empty token",
			req: searchUsersReq{
				token: "",
				Name:  name,
			},
			err: apiutil.ErrBearerToken,
		},
		{
			desc: "empty query",
			req: searchUsersReq{
				token: valid,
			},
			err: apiutil.ErrEmptySearchQuery,
		},
	}
	for _, c := range cases {
		err := c.req.validate()
		assert.Equal(t, c.err, err)
	}
}

func TestListMembersByObjectReqValidate(t *testing.T) {
	cases := []struct {
		desc string
		req  listMembersByObjectReq
		err  error
	}{
		{
			desc: "valid request",
			req: listMembersByObjectReq{
				token:      valid,
				objectKind: "group",
				objectID:   validID,
			},
			err: nil,
		},
		{
			desc: "empty token",
			req: listMembersByObjectReq{
				token:      "",
				objectKind: "group",
				objectID:   validID,
			},
			err: apiutil.ErrBearerToken,
		},
		{
			desc: "empty object kind",
			req: listMembersByObjectReq{
				token:      valid,
				objectKind: "",
				objectID:   validID,
			},
			err: apiutil.ErrMissingMemberKind,
		},
		{
			desc: "empty object id",
			req: listMembersByObjectReq{
				token:      valid,
				objectKind: "group",
				objectID:   "",
			},
			err: apiutil.ErrMissingID,
		},
	}
	for _, c := range cases {
		err := c.req.validate()
		assert.Equal(t, c.err, err)
	}
}

func TestUpdateUserReqValidate(t *testing.T) {
	cases := []struct {
		desc string
		req  updateUserReq
		err  error
	}{
		{
			desc: "valid request",
			req: updateUserReq{
				token: valid,
				id:    validID,
				Name:  valid,
			},
			err: nil,
		},
		{
			desc: "empty token",
			req: updateUserReq{
				token: "",
				id:    validID,
				Name:  valid,
			},
			err: apiutil.ErrBearerToken,
		},
		{
			desc: "empty id",
			req: updateUserReq{
				token: valid,
				id:    "",
				Name:  valid,
			},
			err: apiutil.ErrMissingID,
		},
	}
	for _, c := range cases {
		err := c.req.validate()
		assert.Equal(t, c.err, err, "%s: expected %s got %s\n", c.desc, c.err, err)
	}
}

func TestUpdateUserTagsReqValidate(t *testing.T) {
	cases := []struct {
		desc string
		req  updateUserTagsReq
		err  error
	}{
		{
			desc: "valid request",
			req: updateUserTagsReq{
				token: valid,
				id:    validID,
				Tags:  []string{"tag1", "tag2"},
			},
			err: nil,
		},
		{
			desc: "empty token",
			req: updateUserTagsReq{
				token: "",
				id:    validID,
				Tags:  []string{"tag1", "tag2"},
			},
			err: apiutil.ErrBearerToken,
		},
		{
			desc: "empty id",
			req: updateUserTagsReq{
				token: valid,
				id:    "",
				Tags:  []string{"tag1", "tag2"},
			},
			err: apiutil.ErrMissingID,
		},
	}
	for _, c := range cases {
		err := c.req.validate()
		assert.Equal(t, c.err, err, "%s: expected %s got %s\n", c.desc, c.err, err)
	}
}

func TestUpdateUserRoleReqValidate(t *testing.T) {
	cases := []struct {
		desc string
		req  updateUserRoleReq
		err  error
	}{
		{
			desc: "valid request",
			req: updateUserRoleReq{
				token: valid,
				id:    validID,
				Role:  "admin",
			},
			err: nil,
		},
		{
			desc: "empty token",
			req: updateUserRoleReq{
				token: "",
				id:    validID,
				Role:  "admin",
			},
			err: apiutil.ErrBearerToken,
		},
		{
			desc: "empty id",
			req: updateUserRoleReq{
				token: valid,
				id:    "",
				Role:  "admin",
			},
			err: apiutil.ErrMissingID,
		},
	}
	for _, c := range cases {
		err := c.req.validate()
		assert.Equal(t, c.err, err, "%s: expected %s got %s\n", c.desc, c.err, err)
	}
}

func TestUpdateUserIdentityReqValidate(t *testing.T) {
	cases := []struct {
		desc string
		req  updateUserIdentityReq
		err  error
	}{
		{
			desc: "valid request",
			req: updateUserIdentityReq{
				token:    valid,
				id:       validID,
				Identity: "example@example.com",
			},
			err: nil,
		},
		{
			desc: "empty token",
			req: updateUserIdentityReq{
				token:    "",
				id:       validID,
				Identity: "example@example.com",
			},
			err: apiutil.ErrBearerToken,
		},
		{
			desc: "empty id",
			req: updateUserIdentityReq{
				token:    valid,
				id:       "",
				Identity: "example@example.com",
			},
			err: apiutil.ErrMissingID,
		},
	}
	for _, c := range cases {
		err := c.req.validate()
		assert.Equal(t, c.err, err, "%s: expected %s got %s\n", c.desc, c.err, err)
	}
}

func TestUpdateUserSecretReqValidate(t *testing.T) {
	cases := []struct {
		desc string
		req  updateUserSecretReq
		err  error
	}{
		{
			desc: "valid request",
			req: updateUserSecretReq{
				token:     valid,
				OldSecret: secret,
				NewSecret: secret,
			},
			err: nil,
		},
		{
			desc: "empty token",
			req: updateUserSecretReq{
				token:     "",
				OldSecret: secret,
				NewSecret: secret,
			},
			err: apiutil.ErrBearerToken,
		},
		{
			desc: "missing old secret",
			req: updateUserSecretReq{
				token:     valid,
				OldSecret: "",
				NewSecret: secret,
			},
			err: apiutil.ErrMissingPass,
		},
		{
			desc: "missing new secret",
			req: updateUserSecretReq{
				token:     valid,
				OldSecret: secret,
				NewSecret: "",
			},
			err: apiutil.ErrMissingPass,
		},
		{
			desc: "invalid new secret",
			req: updateUserSecretReq{
				token:     valid,
				OldSecret: secret,
				NewSecret: "invalid",
			},
			err: apiutil.ErrPasswordFormat,
		},
	}
	for _, c := range cases {
		err := c.req.validate()
		assert.Equal(t, c.err, err)
	}
}

func TestChangeUserStatusReqValidate(t *testing.T) {
	cases := []struct {
		desc string
		req  changeUserStatusReq
		err  error
	}{
		{
			desc: "valid request",
			req: changeUserStatusReq{
				token: valid,
				id:    validID,
			},
			err: nil,
		},
		{
			desc: "empty token",
			req: changeUserStatusReq{
				token: "",
				id:    validID,
			},
			err: apiutil.ErrBearerToken,
		},
		{
			desc: "empty id",
			req: changeUserStatusReq{
				token: valid,
				id:    "",
			},
			err: apiutil.ErrMissingID,
		},
	}
	for _, c := range cases {
		err := c.req.validate()
		assert.Equal(t, c.err, err, "%s: expected %s got %s\n", c.desc, c.err, err)
	}
}

func TestLoginUserReqValidate(t *testing.T) {
	cases := []struct {
		desc string
		req  loginUserReq
		err  error
	}{
		{
			desc: "valid request",
			req: loginUserReq{
				Identity: "eaxmple,example.com",
				Secret:   secret,
			},
			err: nil,
		},
		{
			desc: "empty identity",
			req: loginUserReq{
				Identity: "",
				Secret:   secret,
			},
			err: apiutil.ErrMissingIdentity,
		},
		{
			desc: "empty secret",
			req: loginUserReq{
				Identity: "eaxmple,example.com",
				Secret:   "",
			},
			err: apiutil.ErrMissingPass,
		},
	}
	for _, c := range cases {
		err := c.req.validate()
		assert.Equal(t, c.err, err, "%s: expected %s got %s\n", c.desc, c.err, err)
	}
}

func TestTokenReqValidate(t *testing.T) {
	cases := []struct {
		desc string
		req  tokenReq
		err  error
	}{
		{
			desc: "valid request",
			req: tokenReq{
				RefreshToken: valid,
			},
			err: nil,
		},
		{
			desc: "empty token",
			req: tokenReq{
				RefreshToken: "",
			},
			err: apiutil.ErrBearerToken,
		},
	}
	for _, c := range cases {
		err := c.req.validate()
		assert.Equal(t, c.err, err, "%s: expected %s got %s\n", c.desc, c.err, err)
	}
}

func TestPasswResetReqValidate(t *testing.T) {
	cases := []struct {
		desc string
		req  passwResetReq
		err  error
	}{
		{
			desc: "valid request",
			req: passwResetReq{
				Email: "example@example.com",
				Host:  "example.com",
			},
			err: nil,
		},
		{
			desc: "empty email",
			req: passwResetReq{
				Email: "",
				Host:  "example.com",
			},
			err: apiutil.ErrMissingEmail,
		},
		{
			desc: "empty host",
			req: passwResetReq{
				Email: "example@example.com",
				Host:  "",
			},
			err: apiutil.ErrMissingHost,
		},
	}
	for _, c := range cases {
		err := c.req.validate()
		assert.Equal(t, c.err, err, "%s: expected %s got %s\n", c.desc, c.err, err)
	}
}

func TestResetTokenReqValidate(t *testing.T) {
	cases := []struct {
		desc string
		req  resetTokenReq
		err  error
	}{
		{
			desc: "valid request",
			req: resetTokenReq{
				Token:    valid,
				Password: secret,
				ConfPass: secret,
			},
			err: nil,
		},
		{
			desc: "empty token",
			req: resetTokenReq{
				Token:    "",
				Password: secret,
				ConfPass: secret,
			},
			err: apiutil.ErrBearerToken,
		},
		{
			desc: "empty password",
			req: resetTokenReq{
				Token:    valid,
				Password: "",
				ConfPass: secret,
			},
			err: apiutil.ErrMissingPass,
		},
		{
			desc: "empty confpass",
			req: resetTokenReq{
				Token:    valid,
				Password: secret,
				ConfPass: "",
			},
			err: apiutil.ErrMissingConfPass,
		},
		{
			desc: "mismatching password and confpass",
			req: resetTokenReq{
				Token:    valid,
				Password: "secret",
				ConfPass: secret,
			},
			err: apiutil.ErrInvalidResetPass,
		},
	}
	for _, c := range cases {
		err := c.req.validate()
		assert.Equal(t, c.err, err)
	}
}

func TestAssignUsersRequestValidate(t *testing.T) {
	cases := []struct {
		desc string
		req  assignUsersReq
		err  error
	}{
		{
			desc: "valid request",
			req: assignUsersReq{
				token:    valid,
				groupID:  validID,
				UserIDs:  []string{validID},
				Relation: valid,
			},
			err: nil,
		},
		{
			desc: "empty token",
			req: assignUsersReq{
				token:    "",
				groupID:  validID,
				UserIDs:  []string{validID},
				Relation: valid,
			},
			err: apiutil.ErrBearerToken,
		},
		{
			desc: "empty id",
			req: assignUsersReq{
				token:    valid,
				groupID:  "",
				UserIDs:  []string{validID},
				Relation: valid,
			},
			err: apiutil.ErrMissingID,
		},
		{
			desc: "empty users",
			req: assignUsersReq{
				token:    valid,
				groupID:  validID,
				UserIDs:  []string{},
				Relation: valid,
			},
			err: apiutil.ErrEmptyList,
		},
		{
			desc: "empty relation",
			req: assignUsersReq{
				token:    valid,
				groupID:  validID,
				UserIDs:  []string{validID},
				Relation: "",
			},
			err: apiutil.ErrMissingRelation,
		},
	}
	for _, c := range cases {
		err := c.req.validate()
		assert.Equal(t, c.err, err, "%s: expected %s got %s\n", c.desc, c.err, err)
	}
}

func TestUnassignUsersRequestValidate(t *testing.T) {
	cases := []struct {
		desc string
		req  unassignUsersReq
		err  error
	}{
		{
			desc: "valid request",
			req: unassignUsersReq{
				token:    valid,
				groupID:  validID,
				UserIDs:  []string{validID},
				Relation: valid,
			},
			err: nil,
		},
		{
			desc: "empty token",
			req: unassignUsersReq{
				token:    "",
				groupID:  validID,
				UserIDs:  []string{validID},
				Relation: valid,
			},
			err: apiutil.ErrBearerToken,
		},
		{
			desc: "empty id",
			req: unassignUsersReq{
				token:    valid,
				groupID:  "",
				UserIDs:  []string{validID},
				Relation: valid,
			},
			err: apiutil.ErrMissingID,
		},
		{
			desc: "empty users",
			req: unassignUsersReq{
				token:    valid,
				groupID:  validID,
				UserIDs:  []string{},
				Relation: valid,
			},
			err: apiutil.ErrEmptyList,
		},
		{
			desc: "empty relation",
			req: unassignUsersReq{
				token:    valid,
				groupID:  validID,
				UserIDs:  []string{validID},
				Relation: "",
			},
			err: nil,
		},
	}
	for _, c := range cases {
		err := c.req.validate()
		assert.Equal(t, c.err, err, "%s: expected %s got %s\n", c.desc, c.err, err)
	}
}

func TestAssignGroupsRequestValidate(t *testing.T) {
	cases := []struct {
		desc string
		req  assignGroupsReq
		err  error
	}{
		{
			desc: "valid request",
			req: assignGroupsReq{
				token:    valid,
				groupID:  validID,
				GroupIDs: []string{validID},
			},
			err: nil,
		},
		{
			desc: "empty token",
			req: assignGroupsReq{
				token:    "",
				groupID:  validID,
				GroupIDs: []string{validID},
			},
			err: apiutil.ErrBearerToken,
		},
		{
			desc: "empty group id",
			req: assignGroupsReq{
				token:    valid,
				groupID:  "",
				GroupIDs: []string{validID},
			},
			err: apiutil.ErrMissingID,
		},
		{
			desc: "empty user group ids",
			req: assignGroupsReq{
				token:    valid,
				groupID:  validID,
				GroupIDs: []string{},
			},
			err: apiutil.ErrEmptyList,
		},
	}
	for _, c := range cases {
		err := c.req.validate()
		assert.Equal(t, c.err, err, "%s: expected %s got %s\n", c.desc, c.err, err)
	}
}

func TestUnassignGroupsRequestValidate(t *testing.T) {
	cases := []struct {
		desc string
		req  unassignGroupsReq
		err  error
	}{
		{
			desc: "valid request",
			req: unassignGroupsReq{
				token:    valid,
				groupID:  validID,
				GroupIDs: []string{validID},
			},
			err: nil,
		},
		{
			desc: "empty token",
			req: unassignGroupsReq{
				token:    "",
				groupID:  validID,
				GroupIDs: []string{validID},
			},
			err: apiutil.ErrBearerToken,
		},
		{
			desc: "empty group id",
			req: unassignGroupsReq{
				token:    valid,
				groupID:  "",
				GroupIDs: []string{validID},
			},
			err: apiutil.ErrMissingID,
		},
		{
			desc: "empty user group ids",
			req: unassignGroupsReq{
				token:    valid,
				groupID:  validID,
				GroupIDs: []string{},
			},
			err: apiutil.ErrEmptyList,
		},
	}
	for _, c := range cases {
		err := c.req.validate()
		assert.Equal(t, c.err, err, "%s: expected %s got %s\n", c.desc, c.err, err)
	}
}
