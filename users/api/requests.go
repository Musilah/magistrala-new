// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"github.com/absmach/magistrala/internal/api"
	"github.com/absmach/magistrala/pkg/apiutil"
	mgclients "github.com/absmach/magistrala/pkg/clients"
	"github.com/absmach/magistrala/users"
)

const maxLimitSize = 100

type createUserReq struct {
	user  users.User
	token string
}

func (req createUserReq) validate() error {
	if len(req.user.Name) > api.MaxNameSize {
		return apiutil.ErrNameSize
	}
	if len(req.user.UserName) > api.MaxNameSize {
		return apiutil.ErrNameSize
	}
	if len(req.user.FirstName) > api.MaxNameSize {
		return apiutil.ErrNameSize
	}
	if len(req.user.LastName) > api.MaxNameSize {
		return apiutil.ErrNameSize
	}
	if req.user.Credentials.Identity == "" {
		return apiutil.ErrMissingIdentity
	}
	if req.user.Credentials.Secret == "" {
		return apiutil.ErrMissingPass
	}
	if !passRegex.MatchString(req.user.Credentials.Secret) {
		return apiutil.ErrPasswordFormat
	}

	return req.user.Validate()
}

type viewUserReq struct {
	token string
	id    string
}

func (req viewUserReq) validate() error {
	if req.token == "" {
		return apiutil.ErrBearerToken
	}
	if req.id == "" {
		return apiutil.ErrMissingID
	}

	return nil
}

type viewProfileReq struct {
	token string
}

func (req viewProfileReq) validate() error {
	if req.token == "" {
		return apiutil.ErrBearerToken
	}

	return nil
}

type listUsersReq struct {
	token    string
	status   mgclients.Status
	offset   uint64
	limit    uint64
	name     string
	tag      string
	identity string
	metadata mgclients.Metadata // this is a hanging fix for now. using mgclients.page instead of users.page
	order    string
	dir      string
	id       string
}

func (req listUsersReq) validate() error {
	if req.token == "" {
		return apiutil.ErrBearerToken
	}
	if req.limit > maxLimitSize || req.limit < 1 {
		return apiutil.ErrLimitSize
	}
	if req.dir != "" && (req.dir != api.AscDir && req.dir != api.DescDir) {
		return apiutil.ErrInvalidDirection
	}

	return nil
}

type searchUsersReq struct {
	token  string
	Offset uint64
	Limit  uint64
	Name   string
	Id     string
	Order  string
	Dir    string
}

func (req searchUsersReq) validate() error {
	if req.token == "" {
		return apiutil.ErrBearerToken
	}

	if req.Name == "" && req.Id == "" {
		return apiutil.ErrEmptySearchQuery
	}

	return nil
}

type listMembersByObjectReq struct {
	mgclients.Page
	token      string
	objectKind string
	objectID   string
}

func (req listMembersByObjectReq) validate() error {
	if req.token == "" {
		return apiutil.ErrBearerToken
	}
	if req.objectID == "" {
		return apiutil.ErrMissingID
	}
	if req.objectKind == "" {
		return apiutil.ErrMissingMemberKind
	}

	return nil
}

type updateUserReq struct {
	token    string
	id       string
	Name     string         `json:"name,omitempty"`
	Metadata users.Metadata `json:"metadata,omitempty"`
}

func (req updateUserReq) validate() error {
	if req.token == "" {
		return apiutil.ErrBearerToken
	}
	if req.id == "" {
		return apiutil.ErrMissingID
	}

	return nil
}

type updateUserTagsReq struct {
	id    string
	token string
	Tags  []string `json:"tags,omitempty"`
}

func (req updateUserTagsReq) validate() error {
	if req.token == "" {
		return apiutil.ErrBearerToken
	}
	if req.id == "" {
		return apiutil.ErrMissingID
	}

	return nil
}

type updateUserRoleReq struct {
	id    string
	token string
	role  mgclients.Role
	Role  string `json:"role,omitempty"`
}

func (req updateUserRoleReq) validate() error {
	if req.token == "" {
		return apiutil.ErrBearerToken
	}
	if req.id == "" {
		return apiutil.ErrMissingID
	}

	return nil
}

type updateUserIdentityReq struct {
	token    string
	id       string
	Identity string `json:"identity,omitempty"`
}

func (req updateUserIdentityReq) validate() error {
	if req.token == "" {
		return apiutil.ErrBearerToken
	}
	if req.id == "" {
		return apiutil.ErrMissingID
	}

	return nil
}

type updateUserSecretReq struct {
	token     string
	OldSecret string `json:"old_secret,omitempty"`
	NewSecret string `json:"new_secret,omitempty"`
}

func (req updateUserSecretReq) validate() error {
	if req.token == "" {
		return apiutil.ErrBearerToken
	}
	if req.OldSecret == "" || req.NewSecret == "" {
		return apiutil.ErrMissingPass
	}
	if !passRegex.MatchString(req.NewSecret) {
		return apiutil.ErrPasswordFormat
	}

	return nil
}

type changeUserStatusReq struct {
	token string
	id    string
}

func (req changeUserStatusReq) validate() error {
	if req.token == "" {
		return apiutil.ErrBearerToken
	}
	if req.id == "" {
		return apiutil.ErrMissingID
	}

	return nil
}

type loginUserReq struct {
	Identity string `json:"identity,omitempty"`
	Secret   string `json:"secret,omitempty"`
	DomainID string `json:"domain_id,omitempty"`
}

func (req loginUserReq) validate() error {
	if req.Identity == "" {
		return apiutil.ErrMissingIdentity
	}
	if req.Secret == "" {
		return apiutil.ErrMissingPass
	}

	return nil
}

type tokenReq struct {
	RefreshToken string `json:"refresh_token,omitempty"`
	DomainID     string `json:"domain_id,omitempty"`
}

func (req tokenReq) validate() error {
	if req.RefreshToken == "" {
		return apiutil.ErrBearerToken
	}

	return nil
}

type passwResetReq struct {
	Email string `json:"email"`
	Host  string `json:"host"`
}

func (req passwResetReq) validate() error {
	if req.Email == "" {
		return apiutil.ErrMissingEmail
	}
	if req.Host == "" {
		return apiutil.ErrMissingHost
	}

	return nil
}

type resetTokenReq struct {
	Token    string `json:"token"`
	Password string `json:"password"`
	ConfPass string `json:"confirm_password"`
}

func (req resetTokenReq) validate() error {
	if req.Password == "" {
		return apiutil.ErrMissingPass
	}
	if req.ConfPass == "" {
		return apiutil.ErrMissingConfPass
	}
	if req.Token == "" {
		return apiutil.ErrBearerToken
	}
	if req.Password != req.ConfPass {
		return apiutil.ErrInvalidResetPass
	}
	if !passRegex.MatchString(req.ConfPass) {
		return apiutil.ErrPasswordFormat
	}

	return nil
}

type assignUsersReq struct {
	token    string
	groupID  string
	Relation string   `json:"relation"`
	UserIDs  []string `json:"user_ids"`
}

func (req assignUsersReq) validate() error {
	if req.token == "" {
		return apiutil.ErrBearerToken
	}

	if req.Relation == "" {
		return apiutil.ErrMissingRelation
	}

	if req.groupID == "" {
		return apiutil.ErrMissingID
	}

	if len(req.UserIDs) == 0 {
		return apiutil.ErrEmptyList
	}

	return nil
}

type unassignUsersReq struct {
	token    string
	groupID  string
	Relation string   `json:"relation"`
	UserIDs  []string `json:"user_ids"`
}

func (req unassignUsersReq) validate() error {
	if req.token == "" {
		return apiutil.ErrBearerToken
	}

	if req.groupID == "" {
		return apiutil.ErrMissingID
	}

	if len(req.UserIDs) == 0 {
		return apiutil.ErrEmptyList
	}

	return nil
}

type assignGroupsReq struct {
	token    string
	groupID  string
	GroupIDs []string `json:"group_ids"`
}

func (req assignGroupsReq) validate() error {
	if req.token == "" {
		return apiutil.ErrBearerToken
	}

	if req.groupID == "" {
		return apiutil.ErrMissingID
	}

	if len(req.GroupIDs) == 0 {
		return apiutil.ErrEmptyList
	}

	return nil
}

type unassignGroupsReq struct {
	token    string
	groupID  string
	GroupIDs []string `json:"group_ids"`
}

func (req unassignGroupsReq) validate() error {
	if req.token == "" {
		return apiutil.ErrBearerToken
	}

	if req.groupID == "" {
		return apiutil.ErrMissingID
	}

	if len(req.GroupIDs) == 0 {
		return apiutil.ErrEmptyList
	}

	return nil
}
