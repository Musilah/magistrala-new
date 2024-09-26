// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package users_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/absmach/magistrala"
	authsvc "github.com/absmach/magistrala/auth"
	authmocks "github.com/absmach/magistrala/auth/mocks"
	"github.com/absmach/magistrala/internal/testsutil"
	mgclients "github.com/absmach/magistrala/pkg/clients"
	"github.com/absmach/magistrala/pkg/errors"
	repoerr "github.com/absmach/magistrala/pkg/errors/repository"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	"github.com/absmach/magistrala/pkg/uuid"
	"github.com/absmach/magistrala/users"
	"github.com/absmach/magistrala/users/hasher"
	"github.com/absmach/magistrala/users/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var (
	idProvider     = uuid.New()
	phasher        = hasher.New()
	secret         = "strongsecret"
	validCMetadata = users.Metadata{"role": "client"}
	userID         = "d8dd12ef-aa2a-43fe-8ef2-2e4fe514360f"
	user           = users.User{
		ID:          userID,
		Name:        "usersname",
		Tags:        []string{"tag1", "tag2"},
		Credentials: users.Credentials{Identity: "useridentity", Secret: secret},
		Metadata:    validCMetadata,
		Status:      mgclients.EnabledStatus,
	}
	basicUser = users.User{
		Name: "usertname",
		ID:   userID,
	}
	validToken      = "token"
	inValidToken    = "invalid"
	validID         = "d4ebb847-5d0e-4e46-bdd9-b6aceaaa3a22"
	wrongID         = testsutil.GenerateUUID(&testing.T{})
	errHashPassword = errors.New("generate hash from password failed")
)

func newService(selfRegister bool) (users.Service, *mocks.Repository, *authmocks.AuthServiceClient, *authmocks.PolicyServiceClient, *mocks.Emailer) {
	cRepo := new(mocks.Repository)
	auth := new(authmocks.AuthServiceClient)
	policy := new(authmocks.PolicyServiceClient)
	e := new(mocks.Emailer)
	return users.NewService(cRepo, auth, policy, e, phasher, idProvider, selfRegister), cRepo, auth, policy, e
}

func TestRegisterUser(t *testing.T) {
	svc, cRepo, _, policy, _ := newService(true)

	cases := []struct {
		desc                      string
		user                      users.User
		identifyResponse          *magistrala.IdentityRes
		addPoliciesResponse       *magistrala.AddPoliciesRes
		deletePoliciesResponse    *magistrala.DeletePolicyRes
		token                     string
		identifyErr               error
		addPoliciesResponseErr    error
		deletePoliciesResponseErr error
		saveErr                   error
		err                       error
	}{
		{
			desc:                "register new user successfully",
			user:                user,
			addPoliciesResponse: &magistrala.AddPoliciesRes{Added: true},
			token:               validToken,
			err:                 nil,
		},
		{
			desc:                   "register existing user",
			user:                   user,
			addPoliciesResponse:    &magistrala.AddPoliciesRes{Added: true},
			deletePoliciesResponse: &magistrala.DeletePolicyRes{Deleted: true},
			token:                  validToken,
			saveErr:                repoerr.ErrConflict,
			err:                    repoerr.ErrConflict,
		},
		{
			desc: "register a new enabled user with name",
			user: users.User{
				Name: "userWithName",
				Credentials: users.Credentials{
					Identity: "newuserwithname@example.com",
					Secret:   secret,
				},
				Status: mgclients.EnabledStatus,
			},
			addPoliciesResponse: &magistrala.AddPoliciesRes{Added: true},
			err:                 nil,
			token:               validToken,
		},
		{
			desc: "register a new disabled user with name",
			user: users.User{
				Name: "userWithName",
				Credentials: users.Credentials{
					Identity: "newuserwithname@example.com",
					Secret:   secret,
				},
			},
			addPoliciesResponse: &magistrala.AddPoliciesRes{Added: true},
			err:                 nil,
			token:               validToken,
		},
		{
			desc: "register a new user with all fields",
			user: users.User{
				Name: "newusertwithallfields",
				Tags: []string{"tag1", "tag2"},
				Credentials: users.Credentials{
					Identity: "newuserwithallfields@example.com",
					Secret:   secret,
				},
				Metadata: users.Metadata{
					"name": "newuserwithallfields",
				},
				Status: mgclients.EnabledStatus,
			},
			addPoliciesResponse: &magistrala.AddPoliciesRes{Added: true},
			err:                 nil,
			token:               validToken,
		},
		{
			desc: "register a new user with missing identity",
			user: users.User{
				Name: "userWithMissingIdentity",
				Credentials: users.Credentials{
					Secret: secret,
				},
			},
			addPoliciesResponse:    &magistrala.AddPoliciesRes{Added: true},
			deletePoliciesResponse: &magistrala.DeletePolicyRes{Deleted: true},
			saveErr:                errors.ErrMalformedEntity,
			err:                    errors.ErrMalformedEntity,
			token:                  validToken,
		},
		{
			desc: "register a new user with missing secret",
			user: users.User{
				Name: "userWithMissingSecret",
				Credentials: users.Credentials{
					Identity: "userwithmissingsecret@example.com",
					Secret:   "",
				},
			},
			addPoliciesResponse:    &magistrala.AddPoliciesRes{Added: true},
			deletePoliciesResponse: &magistrala.DeletePolicyRes{Deleted: true},
			err:                    nil,
		},
		{
			desc: " register a user with a secret that is too long",
			user: users.User{
				Name: "userWithLongSecret",
				Credentials: users.Credentials{
					Identity: "userwithlongsecret@example.com",
					Secret:   strings.Repeat("a", 73),
				},
			},
			addPoliciesResponse:    &magistrala.AddPoliciesRes{Added: true},
			deletePoliciesResponse: &magistrala.DeletePolicyRes{Deleted: true},
			err:                    repoerr.ErrMalformedEntity,
		},
		{
			desc: "register a new user with invalid status",
			user: users.User{
				Name: "userWithInvalidStatus",
				Credentials: users.Credentials{
					Identity: "user with invalid status",
					Secret:   secret,
				},
				Status: mgclients.AllStatus,
			},
			addPoliciesResponse:    &magistrala.AddPoliciesRes{Added: true},
			deletePoliciesResponse: &magistrala.DeletePolicyRes{Deleted: true},
			err:                    svcerr.ErrInvalidStatus,
		},
		{
			desc: "register a new user with invalid role",
			user: users.User{
				Name: "userWithInvalidRole",
				Credentials: users.Credentials{
					Identity: "userwithinvalidrole@example.com",
					Secret:   secret,
				},
				Role: 2,
			},
			addPoliciesResponse:    &magistrala.AddPoliciesRes{Added: true},
			deletePoliciesResponse: &magistrala.DeletePolicyRes{Deleted: true},
			err:                    svcerr.ErrInvalidRole,
		},
		{
			desc: "register a new user with failed to authorize add policies",
			user: users.User{
				Name: "userWithFailedToAddPolicies",
				Credentials: users.Credentials{
					Identity: "userwithfailedpolicies@example.com",
					Secret:   secret,
				},
				Role: mgclients.AdminRole,
			},
			addPoliciesResponse: &magistrala.AddPoliciesRes{Added: false},
			err:                 svcerr.ErrAuthorization,
		},
		{
			desc: "register a new user with failed to add policies with err",
			user: users.User{
				Name: "userWithFailedToAddPolicies",
				Credentials: users.Credentials{
					Identity: "userwithfailedpolicies@example.com",
					Secret:   secret,
				},
				Role: mgclients.AdminRole,
			},
			addPoliciesResponse:    &magistrala.AddPoliciesRes{Added: true},
			addPoliciesResponseErr: svcerr.ErrAddPolicies,
			err:                    svcerr.ErrAddPolicies,
		},
		{
			desc: "register a new userient with failed to delete policies with err",
			user: users.User{
				Name: "userWithFailedToDeletePolicies",
				Credentials: users.Credentials{
					Identity: "userwithfailedtodelete@example.com",
					Secret:   secret,
				},
				Role: mgclients.AdminRole,
			},
			addPoliciesResponse:       &magistrala.AddPoliciesRes{Added: true},
			deletePoliciesResponse:    &magistrala.DeletePolicyRes{Deleted: false},
			deletePoliciesResponseErr: svcerr.ErrConflict,
			saveErr:                   repoerr.ErrConflict,
			err:                       svcerr.ErrConflict,
		},
		{
			desc: "register a new user with failed to delete policies with failed to delete",
			user: users.User{
				Name: "userWithFailedToDeletePolicies",
				Credentials: users.Credentials{
					Identity: "userwithfailedtodelete@example.com",
					Secret:   secret,
				},
				Role: mgclients.AdminRole,
			},
			addPoliciesResponse:    &magistrala.AddPoliciesRes{Added: true},
			deletePoliciesResponse: &magistrala.DeletePolicyRes{Deleted: false},
			saveErr:                repoerr.ErrConflict,
			err:                    svcerr.ErrConflict,
		},
	}

	for _, tc := range cases {
		authCall := policy.On("AddPolicies", context.Background(), mock.Anything).Return(tc.addPoliciesResponse, tc.addPoliciesResponseErr)
		authCall1 := policy.On("DeletePolicies", context.Background(), mock.Anything).Return(tc.deletePoliciesResponse, tc.deletePoliciesResponseErr)
		repoCall := cRepo.On("Save", context.Background(), mock.Anything).Return(tc.user, tc.saveErr)
		expected, err := svc.RegisterUser(context.Background(), tc.token, tc.user)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if err == nil {
			tc.user.ID = expected.ID
			tc.user.CreatedAt = expected.CreatedAt
			tc.user.UpdatedAt = expected.UpdatedAt
			tc.user.Credentials.Secret = expected.Credentials.Secret
			tc.user.UpdatedBy = expected.UpdatedBy
			assert.Equal(t, tc.user, expected, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.user, expected))
			ok := repoCall.Parent.AssertCalled(t, "Save", context.Background(), mock.Anything)
			assert.True(t, ok, fmt.Sprintf("Save was not called on %s", tc.desc))
		}
		repoCall.Unset()
		authCall1.Unset()
		authCall.Unset()
	}

	svc, cRepo, auth, policy, _ := newService(false)

	cases2 := []struct {
		desc                      string
		user                      users.User
		identifyResponse          *magistrala.IdentityRes
		authorizeResponse         *magistrala.AuthorizeRes
		addPoliciesResponse       *magistrala.AddPoliciesRes
		deletePoliciesResponse    *magistrala.DeletePolicyRes
		token                     string
		identifyErr               error
		authorizeErr              error
		addPoliciesResponseErr    error
		deletePoliciesResponseErr error
		saveErr                   error
		checkSuperAdminErr        error
		err                       error
	}{
		{
			desc:                "register new user successfully as admin",
			user:                user,
			identifyResponse:    &magistrala.IdentityRes{UserId: validID},
			authorizeResponse:   &magistrala.AuthorizeRes{Authorized: true},
			addPoliciesResponse: &magistrala.AddPoliciesRes{Added: true},
			token:               validToken,
			err:                 nil,
		},
		{
			desc:             "register a new user as admin with invalid token",
			user:             user,
			identifyResponse: &magistrala.IdentityRes{},
			identifyErr:      svcerr.ErrAuthentication,
			err:              svcerr.ErrAuthentication,
		},
		{
			desc:              "register  a new user as admin with failed to authorize",
			user:              user,
			identifyResponse:  &magistrala.IdentityRes{UserId: wrongID},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: false},
			token:             validToken,
			identifyErr:       svcerr.ErrAuthorization,
			err:               svcerr.ErrAuthorization,
		},
		{
			desc:               "register a new user as admin with failed check on super admin",
			user:               user,
			identifyResponse:   &magistrala.IdentityRes{UserId: validID},
			authorizeResponse:  &magistrala.AuthorizeRes{Authorized: false},
			token:              validToken,
			checkSuperAdminErr: svcerr.ErrAuthorization,
			err:                svcerr.ErrAuthorization,
		},
	}
	for _, tc := range cases2 {
		authCall := auth.On("Identify", context.Background(), &magistrala.IdentityReq{Token: tc.token}).Return(tc.identifyResponse, tc.identifyErr)
		authCall1 := auth.On("Authorize", context.Background(), mock.Anything).Return(tc.authorizeResponse, tc.authorizeErr)
		repoCall := cRepo.On("CheckSuperAdmin", context.Background(), mock.Anything).Return(tc.checkSuperAdminErr)
		authCall2 := policy.On("AddPolicies", context.Background(), mock.Anything).Return(tc.addPoliciesResponse, tc.addPoliciesResponseErr)
		authCall3 := policy.On("DeletePolicies", context.Background(), mock.Anything).Return(tc.deletePoliciesResponse, tc.deletePoliciesResponseErr)
		repoCall1 := cRepo.On("Save", context.Background(), mock.Anything).Return(tc.user, tc.saveErr)
		expected, err := svc.RegisterUser(context.Background(), tc.token, tc.user)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if err == nil {
			tc.user.ID = expected.ID
			tc.user.CreatedAt = expected.CreatedAt
			tc.user.UpdatedAt = expected.UpdatedAt
			tc.user.Credentials.Secret = expected.Credentials.Secret
			tc.user.UpdatedBy = expected.UpdatedBy
			assert.Equal(t, tc.user, expected, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.user, expected))
			ok := repoCall1.Parent.AssertCalled(t, "Save", context.Background(), mock.Anything)
			assert.True(t, ok, fmt.Sprintf("Save was not called on %s", tc.desc))
		}

		repoCall1.Unset()
		authCall3.Unset()
		authCall2.Unset()
		repoCall.Unset()
		authCall1.Unset()
		authCall.Unset()
	}
}

func TestViewUser(t *testing.T) {
	svc, cRepo, auth, _, _ := newService(true)

	adminID := testsutil.GenerateUUID(t)
	cases := []struct {
		desc                 string
		token                string
		userID               string
		identifyResponse     *magistrala.IdentityRes
		authorizeResponse    *magistrala.AuthorizeRes
		retrieveByIDResponse users.User
		response             users.User
		identifyErr          error
		authorizeErr         error
		retrieveByIDErr      error
		checkSuperAdminErr   error
		err                  error
	}{
		{
			desc:                 "view user as normal user successfully",
			identifyResponse:     &magistrala.IdentityRes{UserId: user.ID},
			retrieveByIDResponse: user,
			response:             user,
			token:                validToken,
			userID:               user.ID,
			err:                  nil,
			checkSuperAdminErr:   svcerr.ErrAuthorization,
		},
		{
			desc:                 "view user with an invalid token",
			token:                inValidToken,
			userID:               userID,
			identifyResponse:     &magistrala.IdentityRes{},
			authorizeResponse:    &magistrala.AuthorizeRes{},
			retrieveByIDResponse: users.User{},
			response:             users.User{},
			identifyErr:          svcerr.ErrAuthentication,
			err:                  svcerr.ErrAuthentication,
		},
		{
			desc:                 "view user as normal user with failed to retrieve user",
			identifyResponse:     &magistrala.IdentityRes{UserId: user.ID},
			retrieveByIDResponse: users.User{},
			token:                validToken,
			userID:               user.ID,
			retrieveByIDErr:      repoerr.ErrNotFound,
			err:                  svcerr.ErrNotFound,
			checkSuperAdminErr:   svcerr.ErrAuthorization,
		},
		{
			desc:                 "view user as admin user successfully",
			identifyResponse:     &magistrala.IdentityRes{UserId: adminID},
			authorizeResponse:    &magistrala.AuthorizeRes{Authorized: true},
			retrieveByIDResponse: user,
			response:             user,
			token:                validToken,
			userID:               user.ID,
			err:                  nil,
		},
		{
			desc:             "view user as admin user with invalid token",
			identifyResponse: &magistrala.IdentityRes{},
			token:            inValidToken,
			identifyErr:      svcerr.ErrAuthentication,
			err:              svcerr.ErrAuthentication,
		},
		{
			desc:               "view user as admin user with invalid ID",
			identifyResponse:   &magistrala.IdentityRes{UserId: wrongID},
			authorizeResponse:  &magistrala.AuthorizeRes{Authorized: false},
			token:              validToken,
			userID:             user.ID,
			identifyErr:        svcerr.ErrAuthorization,
			err:                svcerr.ErrAuthorization,
			checkSuperAdminErr: nil,
		},
		{
			desc:                 "view user as admin user with failed check on super admin",
			identifyResponse:     &magistrala.IdentityRes{UserId: adminID},
			authorizeResponse:    &magistrala.AuthorizeRes{Authorized: false},
			token:                validToken,
			retrieveByIDResponse: basicUser,
			response:             basicUser,
			userID:               user.ID,
			checkSuperAdminErr:   svcerr.ErrAuthorization,
			err:                  nil,
		},
	}

	for _, tc := range cases {
		authCall := auth.On("Identify", context.Background(), &magistrala.IdentityReq{Token: tc.token}).Return(tc.identifyResponse, tc.identifyErr)
		authCall1 := auth.On("Authorize", context.Background(), mock.Anything).Return(tc.authorizeResponse, tc.authorizeErr)
		repoCall := cRepo.On("CheckSuperAdmin", context.Background(), mock.Anything).Return(tc.checkSuperAdminErr)
		repoCall1 := cRepo.On("RetrieveByID", context.Background(), tc.userID).Return(tc.retrieveByIDResponse, tc.retrieveByIDErr)

		rUser, err := svc.ViewUser(context.Background(), tc.token, tc.userID)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		tc.response.Credentials.Secret = ""
		assert.Equal(t, tc.response, rUser, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, rUser))
		if tc.err == nil {
			ok := repoCall1.Parent.AssertCalled(t, "RetrieveByID", context.Background(), tc.userID)
			assert.True(t, ok, fmt.Sprintf("RetrieveByID was not called on %s", tc.desc))
		}

		repoCall1.Unset()
		repoCall.Unset()
		authCall1.Unset()
		authCall.Unset()
	}
}

func TestListUsers(t *testing.T) {
	svc, cRepo, auth, _, _ := newService(true)

	cases := []struct {
		desc                string
		token               string
		page                mgclients.Page // another mgclients.Page
		identifyResponse    *magistrala.IdentityRes
		authorizeResponse   *magistrala.AuthorizeRes
		retrieveAllResponse users.UsersPage
		response            users.UsersPage
		size                uint64
		identifyErr         error
		authorizeErr        error
		retrieveAllErr      error
		superAdminErr       error
		err                 error
	}{
		{
			desc: "list users as admin successfully",
			page: mgclients.Page{
				Total: 1,
			},
			identifyResponse:  &magistrala.IdentityRes{UserId: user.ID},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: true},
			retrieveAllResponse: users.UsersPage{
				Page: mgclients.Page{
					Total: 1,
				},
				Users: []users.User{user},
			},
			response: users.UsersPage{
				Page: mgclients.Page{
					Total: 1,
				},
				Users: []users.User{user},
			},
			token: validToken,
			err:   nil,
		},
		{
			desc: "list users as admin with invalid token",
			page: mgclients.Page{
				Total: 1,
			},
			identifyResponse: &magistrala.IdentityRes{},
			identifyErr:      svcerr.ErrAuthentication,
			err:              svcerr.ErrAuthentication,
		},
		{
			desc: "list users as admin with invalid ID",
			page: mgclients.Page{
				Total: 1,
			},
			identifyResponse:  &magistrala.IdentityRes{UserId: user.ID},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: false},
			token:             validToken,
			authorizeErr:      svcerr.ErrAuthorization,
			err:               svcerr.ErrAuthorization,
		},
		{
			desc: "list users as admin with failed to retrieve users",
			page: mgclients.Page{
				Total: 1,
			},
			identifyResponse:    &magistrala.IdentityRes{UserId: user.ID},
			authorizeResponse:   &magistrala.AuthorizeRes{Authorized: true},
			retrieveAllResponse: users.UsersPage{},
			token:               validToken,
			retrieveAllErr:      repoerr.ErrNotFound,
			err:                 svcerr.ErrViewEntity,
		},
		{
			desc: "list users as admin with failed check on super admin",
			page: mgclients.Page{
				Total: 1,
			},
			identifyResponse:  &magistrala.IdentityRes{UserId: user.ID},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: false},
			token:             validToken,
			superAdminErr:     svcerr.ErrAuthorization,
			err:               svcerr.ErrAuthorization,
		},
		{
			desc: "list users as normal user with failed to retrieve users",
			page: mgclients.Page{
				Total: 1,
			},
			identifyResponse:    &magistrala.IdentityRes{UserId: user.ID},
			authorizeResponse:   &magistrala.AuthorizeRes{Authorized: false},
			retrieveAllResponse: users.UsersPage{},
			token:               validToken,
			retrieveAllErr:      repoerr.ErrNotFound,
			err:                 svcerr.ErrAuthorization,
		},
	}

	for _, tc := range cases {
		authCall := auth.On("Identify", context.Background(), &magistrala.IdentityReq{Token: tc.token}).Return(tc.identifyResponse, tc.identifyErr)
		authCall1 := auth.On("Authorize", context.Background(), mock.Anything).Return(tc.authorizeResponse, tc.authorizeErr)
		repoCall := cRepo.On("CheckSuperAdmin", context.Background(), mock.Anything).Return(tc.superAdminErr)
		repoCall1 := cRepo.On("RetrieveAll", context.Background(), mock.Anything).Return(tc.retrieveAllResponse, tc.retrieveAllErr)
		page, err := svc.ListUsers(context.Background(), tc.token, tc.page)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, page, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, page))
		if tc.err == nil {
			ok := repoCall1.Parent.AssertCalled(t, "RetrieveAll", context.Background(), mock.Anything)
			assert.True(t, ok, fmt.Sprintf("RetrieveAll was not called on %s", tc.desc))
		}
		authCall.Unset()
		authCall1.Unset()
		repoCall.Unset()
		repoCall1.Unset()
	}
}

func TestSearchUsers(t *testing.T) {
	svc, cRepo, auth, _, _ := newService(true)
	cases := []struct {
		desc               string
		token              string
		page               mgclients.Page // another mgclients.Page
		identifyResp       *magistrala.IdentityRes
		authorizeResponse  *magistrala.AuthorizeRes
		response           users.UsersPage
		responseErr        error
		identifyErr        error
		authorizeErr       error
		checkSuperAdminErr error
		err                error
	}{
		{
			desc:  "search users with valid token",
			token: validToken,
			page:  mgclients.Page{Offset: 0, Name: "username", Limit: 100},
			response: users.UsersPage{
				Page:  mgclients.Page{Total: 1, Offset: 0, Limit: 100},
				Users: []users.User{user},
			},
			identifyResp:      &magistrala.IdentityRes{UserId: user.ID},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: true},
		},
		{
			desc:        "search users with invalid token",
			token:       inValidToken,
			page:        mgclients.Page{Offset: 0, Name: "username", Limit: 100}, // another mgclients.Page
			response:    users.UsersPage{},
			responseErr: svcerr.ErrAuthentication,
			err:         svcerr.ErrAuthentication,
		},
		{
			desc:  "search users with id",
			token: validToken,
			page:  mgclients.Page{Offset: 0, Id: "d8dd12ef-aa2a-43fe-8ef2-2e4fe514360f", Limit: 100}, // another mgclients.Page
			response: users.UsersPage{
				Page:  mgclients.Page{Total: 1, Offset: 0, Limit: 100}, // another mgclients.Page
				Users: []users.User{user},
			},
			identifyResp:      &magistrala.IdentityRes{UserId: user.ID},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: true},
		},
		{
			desc:  "search users with random name",
			token: validToken,
			page:  mgclients.Page{Offset: 0, Name: "randomname", Limit: 100},
			response: users.UsersPage{
				Page:  mgclients.Page{Total: 0, Offset: 0, Limit: 100},
				Users: []users.User{},
			},
			identifyResp:      &magistrala.IdentityRes{UserId: user.ID},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: true},
		},
		{
			desc:               "search users as a normal user",
			token:              validToken,
			page:               mgclients.Page{Offset: 0, Identity: "useridentity", Limit: 100},
			response:           users.UsersPage{},
			authorizeResponse:  &magistrala.AuthorizeRes{Authorized: false},
			checkSuperAdminErr: svcerr.ErrAuthorization,
			responseErr:        nil,
		},
	}

	for _, tc := range cases {
		authCall := auth.On("Identify", context.Background(), &magistrala.IdentityReq{Token: tc.token}).Return(tc.identifyResp, tc.identifyErr)
		authCall1 := auth.On("Authorize", context.Background(), mock.Anything).Return(tc.authorizeResponse, tc.authorizeErr)
		repoCall := cRepo.On("CheckSuperAdmin", context.Background(), mock.Anything).Return(tc.checkSuperAdminErr)
		repoCall1 := cRepo.On("SearchUsers", context.Background(), mock.Anything).Return(tc.response, tc.responseErr)
		page, err := svc.SearchUsers(context.Background(), tc.token, tc.page)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, page, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, page))
		authCall.Unset()
		authCall1.Unset()
		repoCall.Unset()
		repoCall1.Unset()
	}
}

func TestUpdateUser(t *testing.T) {
	svc, cRepo, auth, _, _ := newService(true)

	user1 := user
	user2 := user
	user1.Name = "Updated user"
	user2.Metadata = users.Metadata{"role": "test"}
	adminID := testsutil.GenerateUUID(t)

	cases := []struct {
		desc               string
		user               users.User
		identifyResponse   *magistrala.IdentityRes
		authorizeResponse  *magistrala.AuthorizeRes
		updateResponse     users.User
		token              string
		identifyErr        error
		authorizeErr       error
		updateErr          error
		checkSuperAdminErr error
		err                error
	}{
		{
			desc:             "update user name  successfully as normal user",
			user:             user1,
			identifyResponse: &magistrala.IdentityRes{UserId: user1.ID},
			updateResponse:   user1,
			token:            validToken,
			err:              nil,
		},
		{
			desc:             "update metadata successfully as normal user",
			user:             user2,
			identifyResponse: &magistrala.IdentityRes{UserId: user2.ID},
			updateResponse:   user2,
			token:            validToken,
			err:              nil,
		},
		{
			desc:             "update user name as normal user with invalid token",
			user:             user1,
			identifyResponse: &magistrala.IdentityRes{},
			token:            inValidToken,
			identifyErr:      svcerr.ErrAuthentication,
			err:              svcerr.ErrAuthentication,
		},
		{
			desc:             "update user name as normal user with repo error on update",
			user:             user1,
			identifyResponse: &magistrala.IdentityRes{UserId: user1.ID},
			updateResponse:   users.User{},
			token:            validToken,
			updateErr:        errors.ErrMalformedEntity,
			err:              svcerr.ErrUpdateEntity,
		},
		{
			desc:              "update user name as admin successfully",
			user:              user1,
			identifyResponse:  &magistrala.IdentityRes{UserId: adminID},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: true},
			updateResponse:    user1,
			token:             validToken,
			err:               nil,
		},
		{
			desc:              "update user metadata as admin successfully",
			user:              user2,
			identifyResponse:  &magistrala.IdentityRes{UserId: adminID},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: true},
			updateResponse:    user2,
			token:             validToken,
			err:               nil,
		},
		{
			desc:             "update user name as admin with invalid token",
			user:             user1,
			identifyResponse: &magistrala.IdentityRes{},
			identifyErr:      svcerr.ErrAuthentication,
			token:            inValidToken,
			err:              svcerr.ErrAuthentication,
		},
		{
			desc:              "update user name as admin with invalid ID",
			user:              user1,
			identifyResponse:  &magistrala.IdentityRes{UserId: wrongID},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: false},
			token:             validToken,
			err:               svcerr.ErrAuthorization,
		},
		{
			desc:               "update user with failed check on super admin",
			user:               user1,
			identifyResponse:   &magistrala.IdentityRes{UserId: adminID},
			authorizeResponse:  &magistrala.AuthorizeRes{Authorized: false},
			token:              validToken,
			checkSuperAdminErr: svcerr.ErrAuthorization,
			err:                svcerr.ErrAuthorization,
		},
		{
			desc:              "update user name as admin with repo error on update",
			user:              user1,
			identifyResponse:  &magistrala.IdentityRes{UserId: adminID},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: true},
			updateResponse:    users.User{},
			token:             validToken,
			updateErr:         errors.ErrMalformedEntity,
			err:               svcerr.ErrUpdateEntity,
		},
	}

	for _, tc := range cases {
		authCall := auth.On("Identify", context.Background(), &magistrala.IdentityReq{Token: tc.token}).Return(tc.identifyResponse, tc.identifyErr)
		authCall1 := auth.On("Authorize", context.Background(), mock.Anything).Return(tc.authorizeResponse, tc.authorizeErr)
		repoCall := cRepo.On("CheckSuperAdmin", context.Background(), mock.Anything).Return(tc.checkSuperAdminErr)
		repoCall1 := cRepo.On("Update", context.Background(), mock.Anything).Return(tc.updateResponse, tc.err)
		updatedUser, err := svc.UpdateUser(context.Background(), tc.token, tc.user)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		assert.Equal(t, tc.updateResponse, updatedUser, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.updateResponse, updatedUser))

		if tc.err == nil {
			ok := repoCall1.Parent.AssertCalled(t, "Update", context.Background(), mock.Anything)
			assert.True(t, ok, fmt.Sprintf("Update was not called on %s", tc.desc))
		}
		authCall.Unset()
		authCall1.Unset()
		repoCall.Unset()
		repoCall1.Unset()
	}
}

func TestUpdateUserTags(t *testing.T) {
	svc, cRepo, auth, _, _ := newService(true)

	user.Tags = []string{"updated"}
	adminID := testsutil.GenerateUUID(t)

	cases := []struct {
		desc                   string
		user                   users.User
		identifyResponse       *magistrala.IdentityRes
		authorizeResponse      *magistrala.AuthorizeRes
		updateUserTagsResponse users.User
		token                  string
		identifyErr            error
		authorizeErr           error
		updateUserTagsErr      error
		checkSuperAdminErr     error
		err                    error
	}{
		{
			desc:                   "update user tags as normal user successfully",
			user:                   user,
			identifyResponse:       &magistrala.IdentityRes{UserId: user.ID},
			updateUserTagsResponse: user,
			token:                  validToken,
			err:                    nil,
		},
		{
			desc:             "update user tags as normal user with invalid token",
			user:             user,
			identifyResponse: &magistrala.IdentityRes{},
			identifyErr:      svcerr.ErrAuthentication,
			token:            inValidToken,
			err:              svcerr.ErrAuthentication,
		},
		{
			desc:                   "update user tags as normal user with repo error on update",
			user:                   user,
			identifyResponse:       &magistrala.IdentityRes{UserId: user.ID},
			updateUserTagsResponse: users.User{},
			token:                  validToken,
			updateUserTagsErr:      errors.ErrMalformedEntity,
			err:                    svcerr.ErrUpdateEntity,
		},
		{
			desc:              "update user tags as admin successfully",
			user:              user,
			identifyResponse:  &magistrala.IdentityRes{UserId: adminID},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: true},
			token:             validToken,
			err:               nil,
		},
		{
			desc:             "update user tags as admin with invalid token",
			user:             user,
			identifyResponse: &magistrala.IdentityRes{},
			identifyErr:      svcerr.ErrAuthentication,
			token:            inValidToken,
			err:              svcerr.ErrAuthentication,
		},
		{
			desc:              "update user tags as admin with invalid ID",
			user:              user,
			identifyResponse:  &magistrala.IdentityRes{UserId: wrongID},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: false},
			identifyErr:       svcerr.ErrAuthorization,
			token:             validToken,
			err:               svcerr.ErrAuthorization,
		},
		{
			desc:               "update user tags as admin with failed check on super admin",
			user:               user,
			identifyResponse:   &magistrala.IdentityRes{UserId: adminID},
			authorizeResponse:  &magistrala.AuthorizeRes{Authorized: false},
			checkSuperAdminErr: svcerr.ErrAuthorization,
			token:              validToken,
			err:                svcerr.ErrAuthorization,
		},
		{
			desc:                   "update user tags as admin with repo error on update",
			user:                   user,
			identifyResponse:       &magistrala.IdentityRes{UserId: adminID},
			authorizeResponse:      &magistrala.AuthorizeRes{Authorized: true},
			updateUserTagsResponse: users.User{},
			token:                  validToken,
			updateUserTagsErr:      errors.ErrMalformedEntity,
			err:                    svcerr.ErrUpdateEntity,
		},
	}

	for _, tc := range cases {
		authCall := auth.On("Identify", context.Background(), &magistrala.IdentityReq{Token: tc.token}).Return(tc.identifyResponse, tc.identifyErr)
		authCall1 := auth.On("Authorize", context.Background(), mock.Anything).Return(tc.authorizeResponse, tc.authorizeErr)
		repoCall := cRepo.On("CheckSuperAdmin", context.Background(), mock.Anything).Return(tc.checkSuperAdminErr)
		repoCall1 := cRepo.On("UpdateTags", context.Background(), mock.Anything).Return(tc.updateUserTagsResponse, tc.updateUserTagsErr)

		updatedUser, err := svc.UpdateUserTags(context.Background(), tc.token, tc.user)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		assert.Equal(t, tc.updateUserTagsResponse, updatedUser, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.updateUserTagsResponse, updatedUser))
		if tc.err == nil {
			ok := repoCall1.Parent.AssertCalled(t, "UpdateTags", context.Background(), mock.Anything)
			assert.True(t, ok, fmt.Sprintf("UpdateTags was not called on %s", tc.desc))
		}
		authCall.Unset()
		authCall1.Unset()
		repoCall.Unset()
		repoCall1.Unset()
	}
}

func TestUpdateUserIdentity(t *testing.T) {
	svc, cRepo, auth, _, _ := newService(true)

	user2 := user
	user2.Credentials.Identity = "updated@example.com"
	adminID := testsutil.GenerateUUID(t)

	cases := []struct {
		desc                       string
		identity                   string
		token                      string
		id                         string
		identifyResponse           *magistrala.IdentityRes
		authorizeResponse          *magistrala.AuthorizeRes
		updateUserIdentityResponse users.User
		identifyErr                error
		authorizeErr               error
		updateUserIdentityErr      error
		checkSuperAdminErr         error
		err                        error
	}{
		{
			desc:                       "update user as normal user successfully",
			identity:                   "updated@example.com",
			token:                      validToken,
			id:                         user.ID,
			identifyResponse:           &magistrala.IdentityRes{UserId: user.ID},
			updateUserIdentityResponse: user2,
			err:                        nil,
		},
		{
			desc:             "update user identity as normal user with invalid token",
			identity:         "updated@example.com",
			token:            inValidToken,
			id:               user.ID,
			identifyResponse: &magistrala.IdentityRes{},
			identifyErr:      svcerr.ErrAuthentication,
			err:              svcerr.ErrAuthentication,
		},
		{
			desc:                       "update user identity as normal user with repo error on update",
			identity:                   "updated@example.com",
			token:                      validToken,
			id:                         user.ID,
			identifyResponse:           &magistrala.IdentityRes{UserId: user.ID},
			updateUserIdentityResponse: users.User{},
			updateUserIdentityErr:      errors.ErrMalformedEntity,
			err:                        svcerr.ErrUpdateEntity,
		},
		{
			desc:              "update user identity as admin successfully",
			identity:          "updated@example.com",
			token:             validToken,
			id:                user.ID,
			identifyResponse:  &magistrala.IdentityRes{UserId: adminID},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: true},
			err:               nil,
		},
		{
			desc:             "update user identity as admin with invalid token",
			identity:         "updated@example.com",
			token:            inValidToken,
			id:               user.ID,
			identifyResponse: &magistrala.IdentityRes{},
			identifyErr:      svcerr.ErrAuthentication,
			err:              svcerr.ErrAuthentication,
		},
		{
			desc:              "update user identity as admin with invalid ID",
			identity:          "updated@example.com",
			token:             validToken,
			id:                user.ID,
			identifyResponse:  &magistrala.IdentityRes{UserId: wrongID},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: false},
			identifyErr:       svcerr.ErrAuthorization,
			err:               svcerr.ErrAuthorization,
		},
		{
			desc:               "update user identity as admin with failed check on super admin",
			identity:           "updated@example.com",
			token:              validToken,
			id:                 user.ID,
			identifyResponse:   &magistrala.IdentityRes{UserId: adminID},
			authorizeResponse:  &magistrala.AuthorizeRes{Authorized: false},
			checkSuperAdminErr: svcerr.ErrAuthorization,
			err:                svcerr.ErrAuthorization,
		},
		{
			desc:                       "update user identity as admin with repo error on update",
			identity:                   "updated@exmaple.com",
			token:                      validToken,
			id:                         user.ID,
			identifyResponse:           &magistrala.IdentityRes{UserId: adminID},
			authorizeResponse:          &magistrala.AuthorizeRes{Authorized: true},
			updateUserIdentityResponse: users.User{},
			updateUserIdentityErr:      errors.ErrMalformedEntity,
			err:                        svcerr.ErrUpdateEntity,
		},
	}

	for _, tc := range cases {
		authCall := auth.On("Identify", context.Background(), &magistrala.IdentityReq{Token: tc.token}).Return(tc.identifyResponse, tc.identifyErr)
		authCall1 := auth.On("Authorize", context.Background(), mock.Anything).Return(tc.authorizeResponse, tc.authorizeErr)
		repoCall := cRepo.On("CheckSuperAdmin", context.Background(), mock.Anything).Return(tc.checkSuperAdminErr)
		repoCall1 := cRepo.On("UpdateIdentity", context.Background(), mock.Anything).Return(tc.updateUserIdentityResponse, tc.updateUserIdentityErr)

		updatedUser, err := svc.UpdateUserIdentity(context.Background(), tc.token, tc.id, tc.identity)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		assert.Equal(t, tc.updateUserIdentityResponse, updatedUser, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.updateUserIdentityResponse, updatedUser))
		if tc.err == nil {
			ok := repoCall1.Parent.AssertCalled(t, "UpdateIdentity", context.Background(), mock.Anything)
			assert.True(t, ok, fmt.Sprintf("UpdateIdentity was not called on %s", tc.desc))
		}
		authCall.Unset()
		authCall1.Unset()
		repoCall.Unset()
		repoCall1.Unset()
	}
}

func TestUpdateUserRole(t *testing.T) {
	svc, cRepo, auth, policy, _ := newService(true)

	user2 := user
	user.Role = mgclients.AdminRole
	user2.Role = mgclients.UserRole

	superAdminAuthReq := &magistrala.AuthorizeReq{
		SubjectType: authsvc.UserType,
		SubjectKind: authsvc.UsersKind,
		Subject:     user.ID,
		Permission:  authsvc.AdminPermission,
		ObjectType:  authsvc.PlatformType,
		Object:      authsvc.MagistralaObject,
	}

	membershipAuthReq := &magistrala.AuthorizeReq{
		SubjectType: authsvc.UserType,
		SubjectKind: authsvc.UsersKind,
		Subject:     user.ID,
		Permission:  authsvc.MembershipPermission,
		ObjectType:  authsvc.PlatformType,
		Object:      authsvc.MagistralaObject,
	}

	cases := []struct {
		desc                       string
		user                       users.User
		identifyResponse           *magistrala.IdentityRes
		superAdminAuthReq          *magistrala.AuthorizeReq
		membershipAuthReq          *magistrala.AuthorizeReq
		superAdminAuthRes          *magistrala.AuthorizeRes
		membershipAuthRes          *magistrala.AuthorizeRes
		deletePolicyFilterResponse *magistrala.DeletePolicyRes
		addPolicyResponse          *magistrala.AddPolicyRes
		updateRoleResponse         users.User
		token                      string
		identifyErr                error
		authorizeErr               error
		membershipAuthErr          error
		deletePolicyErr            error
		addPolicyErr               error
		updateRoleErr              error
		checkSuperAdminErr         error
		err                        error
	}{
		{
			desc:               "update user role successfully",
			user:               user,
			superAdminAuthReq:  superAdminAuthReq,
			identifyResponse:   &magistrala.IdentityRes{UserId: user.ID},
			membershipAuthReq:  membershipAuthReq,
			membershipAuthRes:  &magistrala.AuthorizeRes{Authorized: true},
			superAdminAuthRes:  &magistrala.AuthorizeRes{Authorized: true},
			addPolicyResponse:  &magistrala.AddPolicyRes{Added: true},
			updateRoleResponse: user,
			token:              validToken,
			err:                nil,
		},
		{
			desc:              "update user role with invalid token",
			user:              user,
			token:             inValidToken,
			superAdminAuthReq: superAdminAuthReq,
			superAdminAuthRes: &magistrala.AuthorizeRes{Authorized: true},
			identifyResponse:  &magistrala.IdentityRes{},
			identifyErr:       svcerr.ErrAuthentication,
			err:               svcerr.ErrAuthentication,
		},
		{
			desc:              "update user role with invalid ID",
			user:              user,
			identifyResponse:  &magistrala.IdentityRes{UserId: wrongID},
			superAdminAuthReq: superAdminAuthReq,
			superAdminAuthRes: &magistrala.AuthorizeRes{Authorized: true},
			token:             validToken,
			identifyErr:       svcerr.ErrAuthorization,
			err:               svcerr.ErrAuthorization,
		},
		{
			desc:               "update user role with failed check on super admin",
			user:               user,
			identifyResponse:   &magistrala.IdentityRes{UserId: user.ID},
			superAdminAuthReq:  superAdminAuthReq,
			superAdminAuthRes:  &magistrala.AuthorizeRes{Authorized: false},
			token:              validToken,
			checkSuperAdminErr: svcerr.ErrAuthorization,
			err:                svcerr.ErrAuthorization,
		},
		{
			desc:              "update user role with failed authorization on add policy",
			user:              user,
			identifyResponse:  &magistrala.IdentityRes{UserId: user.ID},
			superAdminAuthReq: superAdminAuthReq,
			superAdminAuthRes: &magistrala.AuthorizeRes{Authorized: true},
			membershipAuthReq: membershipAuthReq,
			membershipAuthRes: &magistrala.AuthorizeRes{Authorized: true},
			addPolicyResponse: &magistrala.AddPolicyRes{Added: false},
			token:             validToken,
			authorizeErr:      svcerr.ErrAuthorization,
			err:               svcerr.ErrAuthorization,
		},
		{
			desc:              "update user role with failed to add policy",
			user:              user,
			superAdminAuthReq: superAdminAuthReq,
			identifyResponse:  &magistrala.IdentityRes{UserId: user.ID},
			superAdminAuthRes: &magistrala.AuthorizeRes{Authorized: true},
			membershipAuthReq: membershipAuthReq,
			membershipAuthRes: &magistrala.AuthorizeRes{Authorized: true},
			addPolicyResponse: &magistrala.AddPolicyRes{},
			token:             validToken,
			addPolicyErr:      errors.ErrMalformedEntity,
			err:               svcerr.ErrAddPolicies,
		},
		{
			desc:                       "update user role to user role successfully  ",
			user:                       user2,
			identifyResponse:           &magistrala.IdentityRes{UserId: user.ID},
			superAdminAuthReq:          superAdminAuthReq,
			superAdminAuthRes:          &magistrala.AuthorizeRes{Authorized: true},
			membershipAuthReq:          membershipAuthReq,
			membershipAuthRes:          &magistrala.AuthorizeRes{Authorized: true},
			deletePolicyFilterResponse: &magistrala.DeletePolicyRes{Deleted: true},
			updateRoleResponse:         user2,
			token:                      validToken,
			err:                        nil,
		},
		{
			desc:                       "update user role to user role with failed to delete policy",
			user:                       user2,
			superAdminAuthReq:          superAdminAuthReq,
			identifyResponse:           &magistrala.IdentityRes{UserId: user.ID},
			superAdminAuthRes:          &magistrala.AuthorizeRes{Authorized: true},
			membershipAuthReq:          membershipAuthReq,
			membershipAuthRes:          &magistrala.AuthorizeRes{Authorized: true},
			deletePolicyFilterResponse: &magistrala.DeletePolicyRes{Deleted: false},
			updateRoleResponse:         users.User{},
			token:                      validToken,
			deletePolicyErr:            svcerr.ErrAuthorization,
			err:                        svcerr.ErrAuthorization,
		},
		{
			desc:                       "update user role to user role with failed to delete policy with error",
			user:                       user2,
			identifyResponse:           &magistrala.IdentityRes{UserId: user.ID},
			superAdminAuthReq:          superAdminAuthReq,
			superAdminAuthRes:          &magistrala.AuthorizeRes{Authorized: true},
			membershipAuthReq:          membershipAuthReq,
			membershipAuthRes:          &magistrala.AuthorizeRes{Authorized: true},
			deletePolicyFilterResponse: &magistrala.DeletePolicyRes{Deleted: false},
			updateRoleResponse:         users.User{},
			token:                      validToken,
			deletePolicyErr:            svcerr.ErrMalformedEntity,
			err:                        svcerr.ErrDeletePolicies,
		},
		{
			desc:                       "Update user with failed repo update and roll back",
			user:                       user,
			superAdminAuthReq:          superAdminAuthReq,
			identifyResponse:           &magistrala.IdentityRes{UserId: user.ID},
			superAdminAuthRes:          &magistrala.AuthorizeRes{Authorized: true},
			membershipAuthReq:          membershipAuthReq,
			membershipAuthRes:          &magistrala.AuthorizeRes{Authorized: true},
			addPolicyResponse:          &magistrala.AddPolicyRes{Added: true},
			deletePolicyFilterResponse: &magistrala.DeletePolicyRes{Deleted: true},
			updateRoleResponse:         users.User{},
			token:                      validToken,
			updateRoleErr:              svcerr.ErrAuthentication,
			err:                        svcerr.ErrAuthentication,
		},
		{
			desc:                       "Update user with failed repo update and failedroll back",
			user:                       user,
			identifyResponse:           &magistrala.IdentityRes{UserId: user.ID},
			superAdminAuthReq:          superAdminAuthReq,
			superAdminAuthRes:          &magistrala.AuthorizeRes{Authorized: true},
			membershipAuthReq:          membershipAuthReq,
			membershipAuthRes:          &magistrala.AuthorizeRes{Authorized: true},
			addPolicyResponse:          &magistrala.AddPolicyRes{Added: true},
			deletePolicyFilterResponse: &magistrala.DeletePolicyRes{Deleted: false},
			updateRoleResponse:         users.User{},
			token:                      validToken,
			updateRoleErr:              svcerr.ErrAuthentication,
			err:                        svcerr.ErrAuthentication,
		},
		{
			desc:              "update user role with failed MembershipPermission authorization",
			user:              user,
			identifyResponse:  &magistrala.IdentityRes{UserId: user.ID},
			superAdminAuthReq: superAdminAuthReq,
			superAdminAuthRes: &magistrala.AuthorizeRes{Authorized: true},
			membershipAuthReq: membershipAuthReq,
			membershipAuthRes: &magistrala.AuthorizeRes{Authorized: false},
			token:             validToken,
			membershipAuthErr: svcerr.ErrAuthorization,
			err:               svcerr.ErrAuthorization,
		},
	}

	for _, tc := range cases {
		authCall := auth.On("Identify", context.Background(), &magistrala.IdentityReq{Token: tc.token}).Return(tc.identifyResponse, tc.identifyErr)
		authCall1 := auth.On("Authorize", context.Background(), tc.superAdminAuthReq).Return(tc.superAdminAuthRes, tc.authorizeErr)
		repoCall := cRepo.On("CheckSuperAdmin", context.Background(), mock.Anything).Return(tc.checkSuperAdminErr)
		authCall2 := auth.On("Authorize", context.Background(), tc.membershipAuthReq).Return(tc.membershipAuthRes, tc.membershipAuthErr)
		authCall3 := policy.On("AddPolicy", context.Background(), mock.Anything).Return(tc.addPolicyResponse, tc.addPolicyErr)
		authCall4 := policy.On("DeletePolicyFilter", context.Background(), mock.Anything).Return(tc.deletePolicyFilterResponse, tc.deletePolicyErr)
		repoCall1 := cRepo.On("UpdateRole", context.Background(), mock.Anything).Return(tc.updateRoleResponse, tc.updateRoleErr)

		updatedUser, err := svc.UpdateUserRole(context.Background(), tc.token, tc.user)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		assert.Equal(t, tc.updateRoleResponse, updatedUser, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.updateRoleResponse, updatedUser))
		if tc.err == nil {
			ok := repoCall1.Parent.AssertCalled(t, "UpdateRole", context.Background(), mock.Anything)
			assert.True(t, ok, fmt.Sprintf("UpdateRole was not called on %s", tc.desc))
		}
		authCall.Unset()
		authCall1.Unset()
		repoCall.Unset()
		authCall2.Unset()
		authCall3.Unset()
		authCall4.Unset()
		repoCall1.Unset()
	}
}

func TestUpdateUserSecret(t *testing.T) {
	svc, cRepo, auth, _, _ := newService(true)

	newSecret := "newstrongSecret"
	rUser := user
	rUser.Credentials.Secret, _ = phasher.Hash(user.Credentials.Secret)
	responseUser := user
	responseUser.Credentials.Secret = newSecret

	cases := []struct {
		desc                       string
		oldSecret                  string
		newSecret                  string
		token                      string
		identifyResponse           *magistrala.IdentityRes
		retrieveByIDResponse       users.User
		retrieveByIdentityResponse users.User
		updateSecretResponse       users.User
		issueResponse              *magistrala.Token
		response                   users.User
		identifyErr                error
		retrieveByIDErr            error
		retrieveByIdentityErr      error
		updateSecretErr            error
		issueErr                   error
		err                        error
	}{
		{
			desc:                       "update user secret with valid token",
			oldSecret:                  user.Credentials.Secret,
			newSecret:                  newSecret,
			token:                      validToken,
			identifyResponse:           &magistrala.IdentityRes{UserId: user.ID},
			retrieveByIdentityResponse: rUser,
			retrieveByIDResponse:       user,
			updateSecretResponse:       responseUser,
			issueResponse:              &magistrala.Token{AccessToken: validToken},
			response:                   responseUser,
			err:                        nil,
		},
		{
			desc:             "update user secret with invalid token",
			oldSecret:        user.Credentials.Secret,
			newSecret:        newSecret,
			token:            inValidToken,
			identifyResponse: &magistrala.IdentityRes{},
			identifyErr:      svcerr.ErrAuthentication,
			err:              svcerr.ErrAuthentication,
		},
		{
			desc:                 "update user secret with failed to retrieve user by ID",
			oldSecret:            user.Credentials.Secret,
			newSecret:            newSecret,
			token:                validToken,
			identifyResponse:     &magistrala.IdentityRes{UserId: user.ID},
			retrieveByIDResponse: users.User{},
			retrieveByIDErr:      repoerr.ErrNotFound,
			err:                  repoerr.ErrNotFound,
		},
		{
			desc:                       "update user secret with failed to retrieve user by identity",
			oldSecret:                  user.Credentials.Secret,
			newSecret:                  newSecret,
			token:                      validToken,
			identifyResponse:           &magistrala.IdentityRes{UserId: user.ID},
			retrieveByIDResponse:       user,
			retrieveByIdentityResponse: users.User{},
			retrieveByIdentityErr:      repoerr.ErrNotFound,
			err:                        repoerr.ErrNotFound,
		},
		{
			desc:                       "update user secret with invalid old secret",
			oldSecret:                  "invalid",
			newSecret:                  newSecret,
			token:                      validToken,
			identifyResponse:           &magistrala.IdentityRes{UserId: user.ID},
			retrieveByIDResponse:       user,
			retrieveByIdentityResponse: rUser,
			err:                        svcerr.ErrLogin,
		},
		{
			desc:                       "update user secret with too long new secret",
			oldSecret:                  user.Credentials.Secret,
			newSecret:                  strings.Repeat("a", 73),
			token:                      validToken,
			identifyResponse:           &magistrala.IdentityRes{UserId: user.ID},
			retrieveByIDResponse:       user,
			retrieveByIdentityResponse: rUser,
			err:                        repoerr.ErrMalformedEntity,
		},
		{
			desc:                       "update user secret with failed to update secret",
			oldSecret:                  user.Credentials.Secret,
			newSecret:                  newSecret,
			token:                      validToken,
			identifyResponse:           &magistrala.IdentityRes{UserId: user.ID},
			retrieveByIDResponse:       user,
			retrieveByIdentityResponse: rUser,
			updateSecretResponse:       users.User{},
			updateSecretErr:            repoerr.ErrMalformedEntity,
			err:                        svcerr.ErrUpdateEntity,
		},
	}

	for _, tc := range cases {
		authCall := auth.On("Identify", context.Background(), &magistrala.IdentityReq{Token: tc.token}).Return(tc.identifyResponse, tc.identifyErr)
		repoCall := cRepo.On("RetrieveByID", context.Background(), user.ID).Return(tc.retrieveByIDResponse, tc.retrieveByIDErr)
		repoCall1 := cRepo.On("RetrieveByIdentity", context.Background(), user.Credentials.Identity).Return(tc.retrieveByIdentityResponse, tc.retrieveByIdentityErr)
		repoCall2 := cRepo.On("UpdateSecret", context.Background(), mock.Anything).Return(tc.updateSecretResponse, tc.updateSecretErr)
		authCall1 := auth.On("Issue", context.Background(), mock.Anything).Return(tc.issueResponse, tc.issueErr)

		updatedUser, err := svc.UpdateUserSecret(context.Background(), tc.token, tc.oldSecret, tc.newSecret)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, updatedUser, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, updatedUser))
		if tc.err == nil {
			ok := repoCall.Parent.AssertCalled(t, "RetrieveByID", context.Background(), tc.response.ID)
			assert.True(t, ok, fmt.Sprintf("RetrieveByID was not called on %s", tc.desc))
			ok = repoCall1.Parent.AssertCalled(t, "RetrieveByIdentity", context.Background(), tc.response.Credentials.Identity)
			assert.True(t, ok, fmt.Sprintf("RetrieveByIdentity was not called on %s", tc.desc))
			ok = repoCall2.Parent.AssertCalled(t, "UpdateSecret", context.Background(), mock.Anything)
			assert.True(t, ok, fmt.Sprintf("UpdateSecret was not called on %s", tc.desc))
		}
		authCall.Unset()
		repoCall.Unset()
		repoCall1.Unset()
		repoCall2.Unset()
		authCall1.Unset()
	}
}

func TestEnableUser(t *testing.T) {
	svc, cRepo, auth, _, _ := newService(true)

	enabledUser1 := users.User{ID: testsutil.GenerateUUID(t), Credentials: users.Credentials{Identity: "uaer1@example.com", Secret: "password"}, Status: mgclients.EnabledStatus}
	disabledUser1 := users.User{ID: testsutil.GenerateUUID(t), Credentials: users.Credentials{Identity: "uaer3@example.com", Secret: "password"}, Status: mgclients.DisabledStatus}
	endisabledUser1 := disabledUser1
	endisabledUser1.Status = mgclients.EnabledStatus

	cases := []struct {
		desc                 string
		id                   string
		token                string
		user                 users.User
		identifyResponse     *magistrala.IdentityRes
		authorizeResponse    *magistrala.AuthorizeRes
		retrieveByIDResponse users.User
		changeStatusResponse users.User
		response             users.User
		identifyErr          error
		authorizeErr         error
		retrieveByIDErr      error
		changeStatusErr      error
		checkSuperAdminErr   error
		err                  error
	}{
		{
			desc:                 "enable disabled user",
			id:                   disabledUser1.ID,
			token:                validToken,
			user:                 disabledUser1,
			identifyResponse:     &magistrala.IdentityRes{UserId: disabledUser1.ID},
			authorizeResponse:    &magistrala.AuthorizeRes{Authorized: true},
			retrieveByIDResponse: disabledUser1,
			changeStatusResponse: endisabledUser1,
			response:             endisabledUser1,
			err:                  nil,
		},
		{
			desc:             "enable disabled user with invalid token",
			id:               disabledUser1.ID,
			token:            inValidToken,
			user:             disabledUser1,
			identifyResponse: &magistrala.IdentityRes{},
			identifyErr:      svcerr.ErrAuthentication,
			err:              svcerr.ErrAuthentication,
		},
		{
			desc:              "enable disabled user with failed to authorize",
			id:                disabledUser1.ID,
			token:             validToken,
			user:              disabledUser1,
			identifyResponse:  &magistrala.IdentityRes{UserId: disabledUser1.ID},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: false},
			identifyErr:       svcerr.ErrAuthorization,
			err:               svcerr.ErrAuthorization,
		},
		{
			desc:               "enable disabled user with normal user token",
			id:                 disabledUser1.ID,
			token:              validToken,
			user:               disabledUser1,
			identifyResponse:   &magistrala.IdentityRes{UserId: validID},
			authorizeResponse:  &magistrala.AuthorizeRes{Authorized: false},
			checkSuperAdminErr: svcerr.ErrAuthorization,
			err:                svcerr.ErrAuthorization,
		},
		{
			desc:                 "enable disabled user with failed to retrieve user by ID",
			id:                   disabledUser1.ID,
			token:                validToken,
			user:                 disabledUser1,
			identifyResponse:     &magistrala.IdentityRes{UserId: disabledUser1.ID},
			authorizeResponse:    &magistrala.AuthorizeRes{Authorized: true},
			retrieveByIDResponse: users.User{},
			retrieveByIDErr:      repoerr.ErrNotFound,
			err:                  repoerr.ErrNotFound,
		},
		{
			desc:                 "enable already enabled user",
			id:                   enabledUser1.ID,
			token:                validToken,
			user:                 enabledUser1,
			identifyResponse:     &magistrala.IdentityRes{UserId: enabledUser1.ID},
			authorizeResponse:    &magistrala.AuthorizeRes{Authorized: true},
			retrieveByIDResponse: enabledUser1,
			err:                  errors.ErrStatusAlreadyAssigned,
		},
		{
			desc:                 "enable disabled user with failed to change status",
			id:                   disabledUser1.ID,
			token:                validToken,
			user:                 disabledUser1,
			identifyResponse:     &magistrala.IdentityRes{UserId: disabledUser1.ID},
			authorizeResponse:    &magistrala.AuthorizeRes{Authorized: true},
			retrieveByIDResponse: disabledUser1,
			changeStatusResponse: users.User{},
			changeStatusErr:      repoerr.ErrMalformedEntity,
			err:                  svcerr.ErrUpdateEntity,
		},
	}

	for _, tc := range cases {
		authCall := auth.On("Identify", context.Background(), &magistrala.IdentityReq{Token: tc.token}).Return(tc.identifyResponse, tc.identifyErr)
		authCall1 := auth.On("Authorize", context.Background(), mock.Anything).Return(tc.authorizeResponse, tc.authorizeErr)
		repoCall := cRepo.On("CheckSuperAdmin", context.Background(), mock.Anything).Return(tc.checkSuperAdminErr)
		repoCall1 := cRepo.On("RetrieveByID", context.Background(), tc.id).Return(tc.retrieveByIDResponse, tc.retrieveByIDErr)
		repoCall2 := cRepo.On("ChangeStatus", context.Background(), mock.Anything).Return(tc.changeStatusResponse, tc.changeStatusErr)

		_, err := svc.EnableUser(context.Background(), tc.token, tc.id)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if tc.err == nil {
			ok := repoCall1.Parent.AssertCalled(t, "RetrieveByID", context.Background(), tc.id)
			assert.True(t, ok, fmt.Sprintf("RetrieveByID was not called on %s", tc.desc))
			ok = repoCall2.Parent.AssertCalled(t, "ChangeStatus", context.Background(), mock.Anything)
			assert.True(t, ok, fmt.Sprintf("ChangeStatus was not called on %s", tc.desc))
		}
		authCall.Unset()
		authCall1.Unset()
		repoCall.Unset()
		repoCall1.Unset()
		repoCall2.Unset()
	}
}

func TestDisableUser(t *testing.T) {
	svc, cRepo, auth, _, _ := newService(true)

	enabledUser1 := users.User{ID: testsutil.GenerateUUID(t), Credentials: users.Credentials{Identity: "user1@example.com", Secret: "password"}, Status: mgclients.EnabledStatus}
	disabledUser1 := users.User{ID: testsutil.GenerateUUID(t), Credentials: users.Credentials{Identity: "user3@example.com", Secret: "password"}, Status: mgclients.DisabledStatus}
	disenabledUser1 := enabledUser1
	disenabledUser1.Status = mgclients.DisabledStatus

	cases := []struct {
		desc                 string
		id                   string
		token                string
		user                 users.User
		identifyResponse     *magistrala.IdentityRes
		authorizeResponse    *magistrala.AuthorizeRes
		retrieveByIDResponse users.User
		changeStatusResponse users.User
		response             users.User
		identifyErr          error
		authorizeErr         error
		retrieveByIDErr      error
		changeStatusErr      error
		checkSuperAdminErr   error
		err                  error
	}{
		{
			desc:                 "disable enabled user",
			id:                   enabledUser1.ID,
			token:                validToken,
			user:                 enabledUser1,
			identifyResponse:     &magistrala.IdentityRes{UserId: enabledUser1.ID},
			authorizeResponse:    &magistrala.AuthorizeRes{Authorized: true},
			retrieveByIDResponse: enabledUser1,
			changeStatusResponse: disenabledUser1,
			response:             disenabledUser1,
			err:                  nil,
		},
		{
			desc:             "disable enabled user with invalid token",
			id:               enabledUser1.ID,
			token:            inValidToken,
			user:             enabledUser1,
			identifyResponse: &magistrala.IdentityRes{},
			identifyErr:      svcerr.ErrAuthentication,
			err:              svcerr.ErrAuthentication,
		},
		{
			desc:              "disable enabled user with failed to authorize",
			id:                enabledUser1.ID,
			token:             validToken,
			user:              enabledUser1,
			identifyResponse:  &magistrala.IdentityRes{UserId: disabledUser1.ID},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: false},
			identifyErr:       svcerr.ErrAuthorization,
			err:               svcerr.ErrAuthorization,
		},
		{
			desc:               "disable enabled user with normal user token",
			id:                 enabledUser1.ID,
			token:              validToken,
			user:               enabledUser1,
			identifyResponse:   &magistrala.IdentityRes{UserId: validID},
			authorizeResponse:  &magistrala.AuthorizeRes{Authorized: false},
			checkSuperAdminErr: svcerr.ErrAuthorization,
			err:                svcerr.ErrAuthorization,
		},
		{
			desc:                 "disable enabled user with failed to retrieve user by ID",
			id:                   enabledUser1.ID,
			token:                validToken,
			user:                 enabledUser1,
			identifyResponse:     &magistrala.IdentityRes{UserId: enabledUser1.ID},
			authorizeResponse:    &magistrala.AuthorizeRes{Authorized: true},
			retrieveByIDResponse: users.User{},
			retrieveByIDErr:      repoerr.ErrNotFound,
			err:                  repoerr.ErrNotFound,
		},
		{
			desc:                 "disable already disabled user",
			id:                   disabledUser1.ID,
			token:                validToken,
			user:                 disabledUser1,
			identifyResponse:     &magistrala.IdentityRes{UserId: disabledUser1.ID},
			authorizeResponse:    &magistrala.AuthorizeRes{Authorized: true},
			retrieveByIDResponse: disabledUser1,
			err:                  errors.ErrStatusAlreadyAssigned,
		},
		{
			desc:                 "disable enabled user with failed to change status",
			id:                   enabledUser1.ID,
			token:                validToken,
			user:                 enabledUser1,
			identifyResponse:     &magistrala.IdentityRes{UserId: enabledUser1.ID},
			authorizeResponse:    &magistrala.AuthorizeRes{Authorized: true},
			retrieveByIDResponse: enabledUser1,
			changeStatusResponse: users.User{},
			changeStatusErr:      repoerr.ErrMalformedEntity,
			err:                  svcerr.ErrUpdateEntity,
		},
	}

	for _, tc := range cases {
		authCall := auth.On("Identify", context.Background(), &magistrala.IdentityReq{Token: tc.token}).Return(tc.identifyResponse, tc.identifyErr)
		authCall1 := auth.On("Authorize", context.Background(), mock.Anything).Return(tc.authorizeResponse, tc.authorizeErr)
		repoCall := cRepo.On("CheckSuperAdmin", context.Background(), mock.Anything).Return(tc.checkSuperAdminErr)
		repoCall1 := cRepo.On("RetrieveByID", context.Background(), tc.id).Return(tc.retrieveByIDResponse, tc.retrieveByIDErr)
		repoCall2 := cRepo.On("ChangeStatus", context.Background(), mock.Anything).Return(tc.changeStatusResponse, tc.changeStatusErr)

		_, err := svc.DisableUser(context.Background(), tc.token, tc.id)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if tc.err == nil {
			ok := repoCall1.Parent.AssertCalled(t, "RetrieveByID", context.Background(), tc.id)
			assert.True(t, ok, fmt.Sprintf("RetrieveByID was not called on %s", tc.desc))
			ok = repoCall2.Parent.AssertCalled(t, "ChangeStatus", context.Background(), mock.Anything)
			assert.True(t, ok, fmt.Sprintf("ChangeStatus was not called on %s", tc.desc))
		}
		authCall.Unset()
		authCall1.Unset()
		repoCall.Unset()
		repoCall1.Unset()
		repoCall2.Unset()
	}
}

func TestDeleteUser(t *testing.T) {
	svc, cRepo, auth, _, _ := newService(true)

	enabledUser1 := users.User{ID: testsutil.GenerateUUID(t), Credentials: users.Credentials{Identity: "user1@example.com", Secret: "password"}, Status: mgclients.EnabledStatus}
	deletedUser1 := users.User{ID: testsutil.GenerateUUID(t), Credentials: users.Credentials{Identity: "user3@example.com", Secret: "password"}, Status: mgclients.DeletedStatus}
	disenabledUser1 := enabledUser1
	disenabledUser1.Status = mgclients.DeletedStatus

	cases := []struct {
		desc                 string
		id                   string
		token                string
		user                 users.User
		identifyResponse     *magistrala.IdentityRes
		authorizeResponse    *magistrala.AuthorizeRes
		retrieveByIDResponse users.User
		changeStatusResponse users.User
		response             users.User
		identifyErr          error
		authorizeErr         error
		retrieveByIDErr      error
		changeStatusErr      error
		checkSuperAdminErr   error
		err                  error
	}{
		{
			desc:                 "delete enabled user",
			id:                   enabledUser1.ID,
			token:                validToken,
			user:                 enabledUser1,
			identifyResponse:     &magistrala.IdentityRes{UserId: enabledUser1.ID},
			authorizeResponse:    &magistrala.AuthorizeRes{Authorized: true},
			retrieveByIDResponse: enabledUser1,
			changeStatusResponse: disenabledUser1,
			response:             disenabledUser1,
			err:                  nil,
		},
		{
			desc:             "delete enabled user with invalid token",
			id:               enabledUser1.ID,
			token:            inValidToken,
			user:             enabledUser1,
			identifyResponse: &magistrala.IdentityRes{},
			identifyErr:      svcerr.ErrAuthentication,
			err:              svcerr.ErrAuthentication,
		},
		{
			desc:              "delete enabled user with failed to authorize",
			id:                enabledUser1.ID,
			token:             validToken,
			user:              enabledUser1,
			identifyResponse:  &magistrala.IdentityRes{UserId: deletedUser1.ID},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: false},
			err:               svcerr.ErrAuthorization,
		},
		{
			desc:               "delete enabled user with normal user token",
			id:                 enabledUser1.ID,
			token:              validToken,
			user:               enabledUser1,
			identifyResponse:   &magistrala.IdentityRes{UserId: validID},
			authorizeResponse:  &magistrala.AuthorizeRes{Authorized: false},
			checkSuperAdminErr: svcerr.ErrAuthorization,
			err:                svcerr.ErrAuthorization,
		},
		{
			desc:                 "delete enabled user with failed to retrieve user by ID",
			id:                   enabledUser1.ID,
			token:                validToken,
			user:                 enabledUser1,
			identifyResponse:     &magistrala.IdentityRes{UserId: enabledUser1.ID},
			authorizeResponse:    &magistrala.AuthorizeRes{Authorized: true},
			retrieveByIDResponse: users.User{},
			retrieveByIDErr:      repoerr.ErrNotFound,
			err:                  repoerr.ErrNotFound,
		},
		{
			desc:                 "delete already deleted user",
			id:                   deletedUser1.ID,
			token:                validToken,
			user:                 deletedUser1,
			identifyResponse:     &magistrala.IdentityRes{UserId: deletedUser1.ID},
			authorizeResponse:    &magistrala.AuthorizeRes{Authorized: true},
			retrieveByIDResponse: deletedUser1,
			err:                  errors.ErrStatusAlreadyAssigned,
		},
		{
			desc:                 "delete enabled user with failed to change status",
			id:                   enabledUser1.ID,
			token:                validToken,
			user:                 enabledUser1,
			identifyResponse:     &magistrala.IdentityRes{UserId: enabledUser1.ID},
			authorizeResponse:    &magistrala.AuthorizeRes{Authorized: true},
			retrieveByIDResponse: enabledUser1,
			changeStatusResponse: users.User{},
			changeStatusErr:      repoerr.ErrMalformedEntity,
			err:                  svcerr.ErrUpdateEntity,
		},
	}

	for _, tc := range cases {
		repoCall := auth.On("Identify", context.Background(), &magistrala.IdentityReq{Token: tc.token}).Return(tc.identifyResponse, tc.identifyErr)
		repoCall1 := auth.On("Authorize", context.Background(), mock.Anything).Return(tc.authorizeResponse, tc.authorizeErr)
		repoCall2 := cRepo.On("CheckSuperAdmin", context.Background(), mock.Anything).Return(tc.checkSuperAdminErr)
		repoCall3 := cRepo.On("RetrieveByID", context.Background(), tc.id).Return(tc.retrieveByIDResponse, tc.retrieveByIDErr)
		repoCall4 := cRepo.On("ChangeStatus", context.Background(), mock.Anything).Return(tc.changeStatusResponse, tc.changeStatusErr)

		err := svc.DeleteUser(context.Background(), tc.token, tc.id)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if tc.err == nil {
			ok := repoCall3.Parent.AssertCalled(t, "RetrieveByID", context.Background(), tc.id)
			assert.True(t, ok, fmt.Sprintf("RetrieveByID was not called on %s", tc.desc))
			ok = repoCall4.Parent.AssertCalled(t, "ChangeStatus", context.Background(), mock.Anything)
			assert.True(t, ok, fmt.Sprintf("ChangeStatus was not called on %s", tc.desc))
		}
		repoCall.Unset()
		repoCall1.Unset()
		repoCall2.Unset()
		repoCall3.Unset()
		repoCall4.Unset()
	}
}

func TestListMembers(t *testing.T) {
	svc, cRepo, auth, policy, _ := newService(true)

	validPolicy := fmt.Sprintf("%s_%s", validID, user.ID)
	permissionsUser := basicUser
	permissionsUser.Permissions = []string{"read"}

	cases := []struct {
		desc                    string
		token                   string
		groupID                 string
		objectKind              string
		objectID                string
		page                    mgclients.Page
		identifyResponse        *magistrala.IdentityRes
		authorizeReq            *magistrala.AuthorizeReq
		listAllSubjectsReq      *magistrala.ListSubjectsReq
		authorizeResponse       *magistrala.AuthorizeRes
		listAllSubjectsResponse *magistrala.ListSubjectsRes
		retrieveAllResponse     users.UsersPage
		listPermissionsResponse *magistrala.ListPermissionsRes
		response                users.MembersPage
		authorizeErr            error
		listAllSubjectsErr      error
		retrieveAllErr          error
		identifyErr             error
		listPermissionErr       error
		err                     error
	}{
		{
			desc:                    "list members with no policies successfully of the things kind",
			token:                   validToken,
			groupID:                 validID,
			objectKind:              authsvc.ThingsKind,
			objectID:                validID,
			page:                    mgclients.Page{Offset: 0, Limit: 100, Permission: "read"}, // another mgclients.Page
			identifyResponse:        &magistrala.IdentityRes{UserId: user.ID},
			listAllSubjectsResponse: &magistrala.ListSubjectsRes{},
			authorizeReq: &magistrala.AuthorizeReq{
				SubjectType: authsvc.UserType,
				SubjectKind: authsvc.TokenKind,
				Subject:     validToken,
				Permission:  "read",
				ObjectType:  authsvc.ThingType,
				Object:      validID,
			},
			listAllSubjectsReq: &magistrala.ListSubjectsReq{
				SubjectType: authsvc.UserType,
				Permission:  "read",
				Object:      validID,
				ObjectType:  authsvc.ThingType,
			},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: true},
			response: users.MembersPage{
				Page: mgclients.Page{
					Total:  0,
					Offset: 0,
					Limit:  100,
				},
			},
			err: nil,
		},
		{
			desc:             "list members with policies successsfully of the things kind",
			token:            validToken,
			groupID:          validID,
			objectKind:       authsvc.ThingsKind,
			objectID:         validID,
			page:             mgclients.Page{Offset: 0, Limit: 100, Permission: "read"},
			identifyResponse: &magistrala.IdentityRes{UserId: user.ID},
			authorizeReq: &magistrala.AuthorizeReq{
				SubjectType: authsvc.UserType,
				SubjectKind: authsvc.TokenKind,
				Subject:     validToken,
				Permission:  "read",
				ObjectType:  authsvc.ThingType,
				Object:      validID,
			},
			listAllSubjectsReq: &magistrala.ListSubjectsReq{
				SubjectType: authsvc.UserType,
				Permission:  "read",
				Object:      validID,
				ObjectType:  authsvc.ThingType,
			},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: true},
			listAllSubjectsResponse: &magistrala.ListSubjectsRes{
				Policies: []string{validPolicy},
			},
			retrieveAllResponse: users.UsersPage{
				Page: mgclients.Page{
					Total:  1,
					Offset: 0,
					Limit:  100,
				},
				Users: []users.User{user},
			},
			response: users.MembersPage{
				Page: mgclients.Page{
					Total:  1,
					Offset: 0,
					Limit:  100,
				},
				Members: []users.User{basicUser},
			},
			err: nil,
		},
		{
			desc:             "list members with policies successsfully of the things kind with permissions",
			token:            validToken,
			groupID:          validID,
			objectKind:       authsvc.ThingsKind,
			objectID:         validID,
			page:             mgclients.Page{Offset: 0, Limit: 100, Permission: "read", ListPerms: true},
			identifyResponse: &magistrala.IdentityRes{UserId: basicUser.ID},
			authorizeReq: &magistrala.AuthorizeReq{
				SubjectType: authsvc.UserType,
				SubjectKind: authsvc.TokenKind,
				Subject:     validToken,
				Permission:  "read",
				ObjectType:  authsvc.ThingType,
				Object:      validID,
			},
			listAllSubjectsReq: &magistrala.ListSubjectsReq{
				SubjectType: authsvc.UserType,
				Permission:  "read",
				Object:      validID,
				ObjectType:  authsvc.ThingType,
			},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: true},
			listAllSubjectsResponse: &magistrala.ListSubjectsRes{
				Policies: []string{validPolicy},
			},
			retrieveAllResponse: users.UsersPage{
				Page: mgclients.Page{
					Total:  1,
					Offset: 0,
					Limit:  100,
				},
				Users: []users.User{basicUser},
			},
			listPermissionsResponse: &magistrala.ListPermissionsRes{Permissions: []string{"read"}},
			response: users.MembersPage{
				Page: mgclients.Page{
					Total:  1,
					Offset: 0,
					Limit:  100,
				},
				Members: []users.User{permissionsUser},
			},
			err: nil,
		},
		{
			desc:             "list members with policies of the things kind with permissionswith failed list permissions",
			token:            validToken,
			groupID:          validID,
			objectKind:       authsvc.ThingsKind,
			objectID:         validID,
			page:             mgclients.Page{Offset: 0, Limit: 100, Permission: "read", ListPerms: true}, // another mgclients.Page
			identifyResponse: &magistrala.IdentityRes{UserId: user.ID},
			authorizeReq: &magistrala.AuthorizeReq{
				SubjectType: authsvc.UserType,
				SubjectKind: authsvc.TokenKind,
				Subject:     validToken,
				Permission:  "read",
				ObjectType:  authsvc.ThingType,
				Object:      validID,
			},
			listAllSubjectsReq: &magistrala.ListSubjectsReq{
				SubjectType: authsvc.UserType,
				Permission:  "read",
				Object:      validID,
				ObjectType:  authsvc.ThingType,
			},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: true},
			listAllSubjectsResponse: &magistrala.ListSubjectsRes{
				Policies: []string{validPolicy},
			},
			retrieveAllResponse: users.UsersPage{
				Page: mgclients.Page{
					Total:  1,
					Offset: 0,
					Limit:  100,
				},
				Users: []users.User{user},
			},
			listPermissionsResponse: &magistrala.ListPermissionsRes{},
			response:                users.MembersPage{},
			listPermissionErr:       svcerr.ErrNotFound,
			err:                     svcerr.ErrNotFound,
		},
		{
			desc:             "list members with of the things kind with failed to authorize",
			token:            validToken,
			groupID:          validID,
			objectKind:       authsvc.ThingsKind,
			objectID:         validID,
			page:             mgclients.Page{Offset: 0, Limit: 100, Permission: "read"}, // another mgclients.Page
			identifyResponse: &magistrala.IdentityRes{UserId: user.ID},
			authorizeReq: &magistrala.AuthorizeReq{
				SubjectType: authsvc.UserType,
				SubjectKind: authsvc.TokenKind,
				Subject:     validToken,
				Permission:  "read",
				ObjectType:  authsvc.ThingType,
				Object:      validID,
			},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: false},
			err:               svcerr.ErrAuthorization,
		},
		{
			desc:             "list members with of the things kind with failed to list all subjects",
			token:            validToken,
			groupID:          validID,
			objectKind:       authsvc.ThingsKind,
			objectID:         validID,
			page:             mgclients.Page{Offset: 0, Limit: 100, Permission: "read"},
			identifyResponse: &magistrala.IdentityRes{UserId: user.ID},
			authorizeReq: &magistrala.AuthorizeReq{
				SubjectType: authsvc.UserType,
				SubjectKind: authsvc.TokenKind,
				Subject:     validToken,
				Permission:  "read",
				ObjectType:  authsvc.ThingType,
				Object:      validID,
			},
			listAllSubjectsReq: &magistrala.ListSubjectsReq{
				SubjectType: authsvc.UserType,
				Permission:  "read",
				Object:      validID,
				ObjectType:  authsvc.ThingType,
			},
			authorizeResponse:       &magistrala.AuthorizeRes{Authorized: true},
			listAllSubjectsErr:      repoerr.ErrNotFound,
			listAllSubjectsResponse: &magistrala.ListSubjectsRes{},
			err:                     repoerr.ErrNotFound,
		},
		{
			desc:             "list members with of the things kind with failed to retrieve all",
			token:            validToken,
			groupID:          validID,
			objectKind:       authsvc.ThingsKind,
			objectID:         validID,
			page:             mgclients.Page{Offset: 0, Limit: 100, Permission: "read"},
			identifyResponse: &magistrala.IdentityRes{UserId: user.ID},
			authorizeReq: &magistrala.AuthorizeReq{
				SubjectType: authsvc.UserType,
				SubjectKind: authsvc.TokenKind,
				Subject:     validToken,
				Permission:  "read",
				ObjectType:  authsvc.ThingType,
				Object:      validID,
			},
			listAllSubjectsReq: &magistrala.ListSubjectsReq{
				SubjectType: authsvc.UserType,
				Permission:  "read",
				Object:      validID,
				ObjectType:  authsvc.ThingType,
			},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: true},
			listAllSubjectsResponse: &magistrala.ListSubjectsRes{
				Policies: []string{validPolicy},
			},
			retrieveAllResponse: users.UsersPage{},
			response:            users.MembersPage{},
			retrieveAllErr:      repoerr.ErrNotFound,
			err:                 repoerr.ErrNotFound,
		},
		{
			desc:                    "list members with no policies successfully of the domain kind",
			token:                   validToken,
			groupID:                 validID,
			objectKind:              authsvc.DomainsKind,
			objectID:                validID,
			page:                    mgclients.Page{Offset: 0, Limit: 100, Permission: "read"}, // another mgclients.Page
			identifyResponse:        &magistrala.IdentityRes{UserId: user.ID},
			listAllSubjectsResponse: &magistrala.ListSubjectsRes{},
			authorizeReq: &magistrala.AuthorizeReq{
				SubjectType: authsvc.UserType,
				SubjectKind: authsvc.TokenKind,
				Subject:     validToken,
				Permission:  "read",
				ObjectType:  authsvc.DomainType,
				Object:      validID,
			},
			listAllSubjectsReq: &magistrala.ListSubjectsReq{
				SubjectType: authsvc.UserType,
				Permission:  "read",
				Object:      validID,
				ObjectType:  authsvc.DomainType,
			},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: true},
			response: users.MembersPage{
				Page: mgclients.Page{
					Total:  0,
					Offset: 0,
					Limit:  100,
				},
			},
			err: nil,
		},
		{
			desc:             "list members with policies successsfully of the domains kind",
			token:            validToken,
			groupID:          validID,
			objectKind:       authsvc.DomainsKind,
			objectID:         validID,
			page:             mgclients.Page{Offset: 0, Limit: 100, Permission: "read"},
			identifyResponse: &magistrala.IdentityRes{UserId: user.ID},
			authorizeReq: &magistrala.AuthorizeReq{
				SubjectType: authsvc.UserType,
				SubjectKind: authsvc.TokenKind,
				Subject:     validToken,
				Permission:  "read",
				ObjectType:  authsvc.DomainType,
				Object:      validID,
			},
			listAllSubjectsReq: &magistrala.ListSubjectsReq{
				SubjectType: authsvc.UserType,
				Permission:  "read",
				Object:      validID,
				ObjectType:  authsvc.DomainType,
			},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: true},
			listAllSubjectsResponse: &magistrala.ListSubjectsRes{
				Policies: []string{validPolicy},
			},
			retrieveAllResponse: users.UsersPage{
				Page: mgclients.Page{
					Total:  1,
					Offset: 0,
					Limit:  100,
				},
				Users: []users.User{basicUser},
			},
			response: users.MembersPage{
				Page: mgclients.Page{
					Total:  1,
					Offset: 0,
					Limit:  100,
				},
				Members: []users.User{basicUser},
			},
			err: nil,
		},
		{
			desc:             "list members with of the domains kind with failed to authorize",
			token:            validToken,
			groupID:          validID,
			objectKind:       authsvc.DomainsKind,
			objectID:         validID,
			page:             mgclients.Page{Offset: 0, Limit: 100, Permission: "read"},
			identifyResponse: &magistrala.IdentityRes{UserId: user.ID},
			authorizeReq: &magistrala.AuthorizeReq{
				SubjectType: authsvc.UserType,
				SubjectKind: authsvc.TokenKind,
				Subject:     validToken,
				Permission:  "read",
				ObjectType:  authsvc.DomainType,
				Object:      validID,
			},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: false},
			err:               svcerr.ErrAuthorization,
		},
		{
			desc:                    "list members with no policies successfully of the groups kind",
			token:                   validToken,
			groupID:                 validID,
			objectKind:              authsvc.GroupsKind,
			objectID:                validID,
			page:                    mgclients.Page{Offset: 0, Limit: 100, Permission: "read"}, // another mgclients.Page
			identifyResponse:        &magistrala.IdentityRes{UserId: user.ID},
			listAllSubjectsResponse: &magistrala.ListSubjectsRes{},
			authorizeReq: &magistrala.AuthorizeReq{
				SubjectType: authsvc.UserType,
				SubjectKind: authsvc.TokenKind,
				Subject:     validToken,
				Permission:  "read",
				ObjectType:  authsvc.GroupType,
				Object:      validID,
			},
			listAllSubjectsReq: &magistrala.ListSubjectsReq{
				SubjectType: authsvc.UserType,
				Permission:  "read",
				Object:      validID,
				ObjectType:  authsvc.GroupType,
			},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: true},
			response: users.MembersPage{
				Page: mgclients.Page{
					Total:  0,
					Offset: 0,
					Limit:  100,
				},
			},
			err: nil,
		},
		{
			desc:             "list members with policies successsfully of the groups kind",
			token:            validToken,
			groupID:          validID,
			objectKind:       authsvc.GroupsKind,
			objectID:         validID,
			page:             mgclients.Page{Offset: 0, Limit: 100, Permission: "read"},
			identifyResponse: &magistrala.IdentityRes{UserId: user.ID},
			authorizeReq: &magistrala.AuthorizeReq{
				SubjectType: authsvc.UserType,
				SubjectKind: authsvc.TokenKind,
				Subject:     validToken,
				Permission:  "read",
				ObjectType:  authsvc.GroupType,
				Object:      validID,
			},
			listAllSubjectsReq: &magistrala.ListSubjectsReq{
				SubjectType: authsvc.UserType,
				Permission:  "read",
				Object:      validID,
				ObjectType:  authsvc.GroupType,
			},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: true},
			listAllSubjectsResponse: &magistrala.ListSubjectsRes{
				Policies: []string{validPolicy},
			},
			retrieveAllResponse: users.UsersPage{
				Page: mgclients.Page{
					Total:  1,
					Offset: 0,
					Limit:  100,
				},
				Users: []users.User{user},
			},
			response: users.MembersPage{
				Page: mgclients.Page{
					Total:  1,
					Offset: 0,
					Limit:  100,
				},
				Members: []users.User{basicUser},
			},
			err: nil,
		},
		{
			desc:             "list members with invalid token",
			token:            inValidToken,
			page:             mgclients.Page{Offset: 0, Limit: 100, Permission: "read"}, // another mgclients.Page
			identifyResponse: &magistrala.IdentityRes{},
			identifyErr:      svcerr.ErrAuthentication,
			err:              svcerr.ErrAuthentication,
		},
	}

	for _, tc := range cases {
		authCall := auth.On("Identify", context.Background(), &magistrala.IdentityReq{Token: tc.token}).Return(tc.identifyResponse, tc.identifyErr)
		authCall1 := auth.On("Authorize", context.Background(), tc.authorizeReq).Return(tc.authorizeResponse, tc.authorizeErr)
		authCall2 := policy.On("ListAllSubjects", context.Background(), tc.listAllSubjectsReq).Return(tc.listAllSubjectsResponse, tc.listAllSubjectsErr)
		repoCall := cRepo.On("RetrieveAll", context.Background(), mock.Anything).Return(tc.retrieveAllResponse, tc.retrieveAllErr)
		authCall3 := policy.On("ListPermissions", mock.Anything, mock.Anything).Return(tc.listPermissionsResponse, tc.listPermissionErr)

		page, err := svc.ListMembers(context.Background(), tc.token, tc.objectKind, tc.objectID, tc.page)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, page, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, page))

		authCall.Unset()
		authCall1.Unset()
		authCall2.Unset()
		repoCall.Unset()
		authCall3.Unset()
	}
}

func TestIssueToken(t *testing.T) {
	svc, cRepo, auth, _, _ := newService(true)

	rUser := user
	rUser2 := user
	rUser3 := user
	rUser.Credentials.Secret, _ = phasher.Hash(user.Credentials.Secret)
	rUser2.Credentials.Secret = "wrongsecret"
	rUser3.Credentials.Secret, _ = phasher.Hash("wrongsecret")

	cases := []struct {
		desc                       string
		domainID                   string
		user                       users.User
		retrieveByIdentityResponse users.User
		issueResponse              *magistrala.Token
		retrieveByIdentityErr      error
		issueErr                   error
		err                        error
	}{
		{
			desc:                       "issue token for an existing user",
			user:                       user,
			retrieveByIdentityResponse: rUser,
			issueResponse:              &magistrala.Token{AccessToken: validToken, RefreshToken: &validToken, AccessType: "3"},
			err:                        nil,
		},
		{
			desc:                       "issue token for non-empty domain id",
			domainID:                   validID,
			user:                       user,
			retrieveByIdentityResponse: rUser,
			issueResponse:              &magistrala.Token{AccessToken: validToken, RefreshToken: &validToken, AccessType: "3"},
			err:                        nil,
		},
		{
			desc:                       "issue token for a non-existing user",
			user:                       user,
			retrieveByIdentityResponse: users.User{},
			retrieveByIdentityErr:      repoerr.ErrNotFound,
			err:                        repoerr.ErrNotFound,
		},
		{
			desc:                       "issue token for a user with wrong secret",
			user:                       user,
			retrieveByIdentityResponse: rUser3,
			err:                        svcerr.ErrLogin,
		},
		{
			desc:                       "issue token with empty domain id",
			user:                       user,
			retrieveByIdentityResponse: rUser,
			issueResponse:              &magistrala.Token{},
			issueErr:                   svcerr.ErrAuthentication,
			err:                        svcerr.ErrAuthentication,
		},
		{
			desc:                       "issue token with grpc error",
			user:                       user,
			retrieveByIdentityResponse: rUser,
			issueResponse:              &magistrala.Token{},
			issueErr:                   svcerr.ErrAuthentication,
			err:                        svcerr.ErrAuthentication,
		},
	}

	for _, tc := range cases {
		repoCall := cRepo.On("RetrieveByIdentity", context.Background(), tc.user.Credentials.Identity).Return(tc.retrieveByIdentityResponse, tc.retrieveByIdentityErr)
		authCall := auth.On("Issue", context.Background(), &magistrala.IssueReq{UserId: tc.user.ID, DomainId: &tc.domainID, Type: uint32(authsvc.AccessKey)}).Return(tc.issueResponse, tc.issueErr)
		token, err := svc.IssueToken(context.Background(), tc.user.Credentials.Identity, tc.user.Credentials.Secret, tc.domainID)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if err == nil {
			assert.NotEmpty(t, token.GetAccessToken(), fmt.Sprintf("%s: expected %s not to be empty\n", tc.desc, token.GetAccessToken()))
			assert.NotEmpty(t, token.GetRefreshToken(), fmt.Sprintf("%s: expected %s not to be empty\n", tc.desc, token.GetRefreshToken()))
			ok := repoCall.Parent.AssertCalled(t, "RetrieveByIdentity", context.Background(), tc.user.Credentials.Identity)
			assert.True(t, ok, fmt.Sprintf("RetrieveByIdentity was not called on %s", tc.desc))
			ok = authCall.Parent.AssertCalled(t, "Issue", context.Background(), &magistrala.IssueReq{UserId: tc.user.ID, DomainId: &tc.domainID, Type: uint32(authsvc.AccessKey)})
			assert.True(t, ok, fmt.Sprintf("Issue was not called on %s", tc.desc))
		}
		authCall.Unset()
		repoCall.Unset()
	}
}

func TestRefreshToken(t *testing.T) {
	svc, crepo, auth, _, _ := newService(true)

	rUser := user
	rUser.Credentials.Secret, _ = phasher.Hash(user.Credentials.Secret)

	cases := []struct {
		desc         string
		token        string
		domainID     string
		identifyResp *magistrala.IdentityRes
		identifyErr  error
		refreshResp  *magistrala.Token
		refresErr    error
		repoResp     users.User
		repoErr      error
		err          error
	}{
		{
			desc:         "refresh token with refresh token for an existing user",
			token:        validToken,
			domainID:     validID,
			identifyResp: &magistrala.IdentityRes{UserId: user.ID},
			refreshResp:  &magistrala.Token{AccessToken: validToken, RefreshToken: &validToken, AccessType: "3"},
			repoResp:     rUser,
			err:          nil,
		},
		{
			desc:         "refresh token with refresh token for empty domain id",
			token:        validToken,
			identifyResp: &magistrala.IdentityRes{UserId: user.ID},
			refreshResp:  &magistrala.Token{AccessToken: validToken, RefreshToken: &validToken, AccessType: "3"},
			repoResp:     rUser,
			err:          nil,
		},
		{
			desc:         "refresh token with access token for an existing user",
			token:        validToken,
			domainID:     validID,
			identifyResp: &magistrala.IdentityRes{UserId: user.ID},
			refreshResp:  &magistrala.Token{},
			refresErr:    svcerr.ErrAuthentication,
			repoResp:     rUser,
			err:          svcerr.ErrAuthentication,
		},
		{
			desc:         "refresh token with invalid token",
			token:        validToken,
			domainID:     validID,
			identifyResp: &magistrala.IdentityRes{},
			identifyErr:  svcerr.ErrAuthentication,
			err:          svcerr.ErrAuthentication,
		},
		{
			desc:         "refresh token with refresh token for a non-existing user",
			token:        validToken,
			domainID:     validID,
			identifyResp: &magistrala.IdentityRes{UserId: user.ID},
			repoErr:      repoerr.ErrNotFound,
			err:          repoerr.ErrNotFound,
		},
		{
			desc:         "refresh token with refresh token for a disable user",
			token:        validToken,
			domainID:     validID,
			identifyResp: &magistrala.IdentityRes{UserId: user.ID},
			repoResp:     users.User{Status: mgclients.DisabledStatus},
			err:          svcerr.ErrAuthentication,
		},
		{
			desc:         "refresh token with empty domain id",
			token:        validToken,
			identifyResp: &magistrala.IdentityRes{UserId: user.ID},
			refreshResp:  &magistrala.Token{},
			refresErr:    svcerr.ErrAuthentication,
			repoResp:     rUser,
			err:          svcerr.ErrAuthentication,
		},
	}

	for _, tc := range cases {
		authCall := auth.On("Identify", context.Background(), &magistrala.IdentityReq{Token: tc.token}).Return(tc.identifyResp, tc.identifyErr)
		authCall1 := auth.On("Refresh", context.Background(), &magistrala.RefreshReq{RefreshToken: tc.token, DomainId: &tc.domainID}).Return(tc.refreshResp, tc.refresErr)
		repoCall := crepo.On("RetrieveByID", context.Background(), tc.identifyResp.GetUserId()).Return(tc.repoResp, tc.repoErr)
		token, err := svc.RefreshToken(context.Background(), tc.token, tc.domainID)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if err == nil {
			assert.NotEmpty(t, token.GetAccessToken(), fmt.Sprintf("%s: expected %s not to be empty\n", tc.desc, token.GetAccessToken()))
			assert.NotEmpty(t, token.GetRefreshToken(), fmt.Sprintf("%s: expected %s not to be empty\n", tc.desc, token.GetRefreshToken()))
			ok := authCall.Parent.AssertCalled(t, "Identify", context.Background(), &magistrala.IdentityReq{Token: tc.token})
			assert.True(t, ok, fmt.Sprintf("Identify was not called on %s", tc.desc))
			ok = authCall.Parent.AssertCalled(t, "Refresh", context.Background(), &magistrala.RefreshReq{RefreshToken: tc.token, DomainId: &tc.domainID})
			assert.True(t, ok, fmt.Sprintf("Refresh was not called on %s", tc.desc))
			ok = repoCall.Parent.AssertCalled(t, "RetrieveByID", context.Background(), tc.identifyResp.UserId)
			assert.True(t, ok, fmt.Sprintf("RetrieveByID was not called on %s", tc.desc))
		}
		authCall.Unset()
		authCall1.Unset()
		repoCall.Unset()
	}
}

func TestGenerateResetToken(t *testing.T) {
	svc, cRepo, auth, _, e := newService(true)

	cases := []struct {
		desc                       string
		email                      string
		host                       string
		retrieveByIdentityResponse users.User
		issueResponse              *magistrala.Token
		retrieveByIdentityErr      error
		issueErr                   error
		err                        error
	}{
		{
			desc:                       "generate reset token for existing user",
			email:                      "existingemail@example.com",
			host:                       "examplehost",
			retrieveByIdentityResponse: user,
			issueResponse:              &magistrala.Token{AccessToken: validToken, RefreshToken: &validToken, AccessType: "3"},
			err:                        nil,
		},
		{
			desc:  "generate reset token for user with non-existing user",
			email: "example@example.com",
			host:  "examplehost",
			retrieveByIdentityResponse: users.User{
				ID: testsutil.GenerateUUID(t),
				Credentials: users.Credentials{
					Identity: "",
				},
			},
			retrieveByIdentityErr: repoerr.ErrNotFound,
			err:                   repoerr.ErrNotFound,
		},
		{
			desc:                       "generate reset token with failed to issue token",
			email:                      "existingemail@example.com",
			host:                       "examplehost",
			retrieveByIdentityResponse: user,
			issueResponse:              &magistrala.Token{},
			issueErr:                   svcerr.ErrAuthorization,
			err:                        svcerr.ErrAuthorization,
		},
	}

	for _, tc := range cases {
		repoCall := cRepo.On("RetrieveByIdentity", context.Background(), tc.email).Return(tc.retrieveByIdentityResponse, tc.retrieveByIdentityErr)
		authCall := auth.On("Issue", context.Background(), mock.Anything).Return(tc.issueResponse, tc.issueErr)

		svcCall := e.On("SendPasswordReset", []string{tc.email}, tc.host, user.Name, validToken).Return(tc.err)
		err := svc.GenerateResetToken(context.Background(), tc.email, tc.host)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		repoCall.Parent.AssertCalled(t, "RetrieveByIdentity", context.Background(), tc.email)
		repoCall.Unset()
		authCall.Unset()
		svcCall.Unset()
	}
}

func TestResetSecret(t *testing.T) {
	svc, cRepo, auth, _, _ := newService(true)

	user := users.User{
		ID: "clientID",
		Credentials: users.Credentials{
			Identity: "test@example.com",
			Secret:   "Strongsecret",
		},
	}

	cases := []struct {
		desc                 string
		token                string
		newSecret            string
		identifyResponse     *magistrala.IdentityRes
		retrieveByIDResponse users.User
		updateSecretResponse users.User
		identifyErr          error
		retrieveByIDErr      error
		updateSecretErr      error
		err                  error
	}{
		{
			desc:                 "reset secret with successfully",
			token:                validToken,
			newSecret:            "newStrongSecret",
			identifyResponse:     &magistrala.IdentityRes{UserId: user.ID},
			retrieveByIDResponse: user,
			updateSecretResponse: users.User{
				ID: "clientID",
				Credentials: users.Credentials{
					Identity: "test@example.com",
					Secret:   "newStrongSecret",
				},
			},
			err: nil,
		},
		{
			desc:             "reset secret with invalid token",
			token:            inValidToken,
			newSecret:        "newStrongSecret",
			identifyResponse: &magistrala.IdentityRes{},
			identifyErr:      svcerr.ErrAuthentication,
			err:              svcerr.ErrAuthentication,
		},
		{
			desc:                 "reset secret with invalid ID",
			token:                validToken,
			newSecret:            "newStrongSecret",
			identifyResponse:     &magistrala.IdentityRes{UserId: wrongID},
			retrieveByIDResponse: users.User{},
			retrieveByIDErr:      repoerr.ErrNotFound,
			err:                  repoerr.ErrNotFound,
		},
		{
			desc:             "reset secret with empty identity",
			token:            validToken,
			newSecret:        "newStrongSecret",
			identifyResponse: &magistrala.IdentityRes{UserId: user.ID},
			retrieveByIDResponse: users.User{
				ID: "clientID",
				Credentials: users.Credentials{
					Identity: "",
				},
			},
			err: nil,
		},
		{
			desc:                 "reset secret with failed to update secret",
			token:                validToken,
			newSecret:            "newStrongSecret",
			identifyResponse:     &magistrala.IdentityRes{UserId: user.ID},
			retrieveByIDResponse: user,
			updateSecretResponse: users.User{},
			updateSecretErr:      svcerr.ErrUpdateEntity,
			err:                  svcerr.ErrAuthorization,
		},
		{
			desc:                 "reset secret with a too long secret",
			token:                validToken,
			newSecret:            strings.Repeat("strongSecret", 10),
			identifyResponse:     &magistrala.IdentityRes{UserId: user.ID},
			retrieveByIDResponse: user,
			err:                  errHashPassword,
		},
	}

	for _, tc := range cases {
		authCall := auth.On("Identify", context.Background(), &magistrala.IdentityReq{Token: tc.token}).Return(tc.identifyResponse, tc.identifyErr)
		repoCall := cRepo.On("RetrieveByID", context.Background(), mock.Anything).Return(tc.retrieveByIDResponse, tc.retrieveByIDErr)
		repoCall1 := cRepo.On("UpdateSecret", context.Background(), mock.Anything).Return(tc.updateSecretResponse, tc.updateSecretErr)

		err := svc.ResetSecret(context.Background(), tc.token, tc.newSecret)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))

		repoCall1.Parent.AssertCalled(t, "UpdateSecret", context.Background(), mock.Anything)
		repoCall.Parent.AssertCalled(t, "RetrieveByID", context.Background(), user.ID)
		authCall.Parent.AssertCalled(t, "Identify", mock.Anything, mock.Anything)
		authCall.Unset()
		repoCall1.Unset()
		repoCall.Unset()
	}
}

func TestViewProfile(t *testing.T) {
	svc, cRepo, auth, _, _ := newService(true)

	client := users.User{
		ID: "clientID",
		Credentials: users.Credentials{
			Identity: "existingIdentity",
			Secret:   "Strongsecret",
		},
	}
	cases := []struct {
		desc                 string
		token                string
		user                 users.User
		identifyResponse     *magistrala.IdentityRes
		retrieveByIDResponse users.User
		identifyErr          error
		retrieveByIDErr      error
		err                  error
	}{
		{
			desc:                 "view profile successfully",
			token:                validToken,
			user:                 user,
			identifyResponse:     &magistrala.IdentityRes{UserId: validID},
			retrieveByIDResponse: client,
			err:                  nil,
		},
		{
			desc:             "view profile with invalid token",
			token:            inValidToken,
			user:             user,
			identifyResponse: &magistrala.IdentityRes{},
			identifyErr:      svcerr.ErrAuthentication,
			err:              svcerr.ErrAuthentication,
		},
		{
			desc:                 "view profile with invalid ID",
			token:                validToken,
			user:                 user,
			identifyResponse:     &magistrala.IdentityRes{UserId: wrongID},
			retrieveByIDResponse: users.User{},
			retrieveByIDErr:      repoerr.ErrNotFound,
			err:                  repoerr.ErrNotFound,
		},
	}

	for _, tc := range cases {
		authCall := auth.On("Identify", context.Background(), mock.Anything).Return(tc.identifyResponse, tc.identifyErr)
		repoCall := cRepo.On("RetrieveByID", context.Background(), mock.Anything).Return(tc.retrieveByIDResponse, tc.retrieveByIDErr)

		_, err := svc.ViewProfile(context.Background(), tc.token)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))

		authCall.Parent.AssertCalled(t, "Identify", mock.Anything, mock.Anything)
		repoCall.Parent.AssertCalled(t, "RetrieveByID", context.Background(), mock.Anything)
		authCall.Unset()
		repoCall.Unset()
	}
}

func TestOAuthCallback(t *testing.T) {
	svc, cRepo, auth, policy, _ := newService(true)

	cases := []struct {
		desc                       string
		user                       users.User
		retrieveByIdentityResponse users.User
		retrieveByIdentityErr      error
		addPoliciesResponse        *magistrala.AddPoliciesRes
		addPoliciesErr             error
		saveResponse               users.User
		saveErr                    error
		deletePoliciesResponse     *magistrala.DeletePolicyRes
		deletePoliciesErr          error
		authorizeResponse          *magistrala.AuthorizeRes
		authorizeErr               error
		issueResponse              *magistrala.Token
		issueErr                   error
		err                        error
	}{
		{
			desc: "oauth signin callback with successfully",
			user: users.User{
				Credentials: users.Credentials{
					Identity: "test@example.com",
				},
			},
			retrieveByIdentityResponse: users.User{
				ID:   testsutil.GenerateUUID(t),
				Role: mgclients.UserRole,
			},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: true},
			issueResponse: &magistrala.Token{
				AccessToken:  strings.Repeat("a", 10),
				RefreshToken: &validToken,
				AccessType:   "Bearer",
			},
			err: nil,
		},
		{
			desc: "oauth signup callback with successfully",
			user: users.User{
				Credentials: users.Credentials{
					Identity: "test@example.com",
				},
			},
			retrieveByIdentityErr: repoerr.ErrNotFound,
			addPoliciesResponse: &magistrala.AddPoliciesRes{
				Added: true,
			},
			saveResponse: users.User{
				ID:   testsutil.GenerateUUID(t),
				Role: mgclients.UserRole,
			},
			issueResponse: &magistrala.Token{
				AccessToken:  strings.Repeat("a", 10),
				RefreshToken: &validToken,
				AccessType:   "Bearer",
			},
			err: nil,
		},
		{
			desc: "oauth signup callback with unknown error",
			user: users.User{
				Credentials: users.Credentials{
					Identity: "test@example.com",
				},
			},
			retrieveByIdentityErr: repoerr.ErrMalformedEntity,
			err:                   repoerr.ErrMalformedEntity,
		},
		{
			desc: "oauth signup callback with failed to register user",
			user: users.User{
				Credentials: users.Credentials{
					Identity: "test@example.com",
				},
			},
			retrieveByIdentityErr: repoerr.ErrNotFound,
			addPoliciesResponse:   &magistrala.AddPoliciesRes{Added: false},
			addPoliciesErr:        svcerr.ErrAuthorization,
			err:                   svcerr.ErrAuthorization,
		},
		{
			desc: "oauth signin callback with user not in the platform",
			user: users.User{
				Credentials: users.Credentials{
					Identity: "test@example.com",
				},
			},
			retrieveByIdentityResponse: users.User{
				ID:   testsutil.GenerateUUID(t),
				Role: mgclients.UserRole,
			},
			authorizeResponse:   &magistrala.AuthorizeRes{Authorized: false},
			authorizeErr:        svcerr.ErrAuthorization,
			addPoliciesResponse: &magistrala.AddPoliciesRes{Added: true},
			issueResponse: &magistrala.Token{
				AccessToken:  strings.Repeat("a", 10),
				RefreshToken: &validToken,
				AccessType:   "Bearer",
			},
			err: nil,
		},
		{
			desc: "oauth signin callback with user not in the platform and failed to add policy",
			user: users.User{
				Credentials: users.Credentials{
					Identity: "test@example.com",
				},
			},
			retrieveByIdentityResponse: users.User{
				ID:   testsutil.GenerateUUID(t),
				Role: mgclients.UserRole,
			},
			authorizeResponse:   &magistrala.AuthorizeRes{Authorized: false},
			authorizeErr:        svcerr.ErrAuthorization,
			addPoliciesResponse: &magistrala.AddPoliciesRes{Added: false},
			addPoliciesErr:      svcerr.ErrAuthorization,
			err:                 svcerr.ErrAuthorization,
		},
		{
			desc: "oauth signin callback with failed to issue token",
			user: users.User{
				Credentials: users.Credentials{
					Identity: "test@example.com",
				},
			},
			retrieveByIdentityResponse: users.User{
				ID:   testsutil.GenerateUUID(t),
				Role: mgclients.UserRole,
			},
			authorizeResponse: &magistrala.AuthorizeRes{Authorized: true},
			issueErr:          svcerr.ErrAuthorization,
			err:               svcerr.ErrAuthorization,
		},
	}
	for _, tc := range cases {
		id := tc.saveResponse.ID
		if tc.retrieveByIdentityResponse.ID != "" {
			id = tc.retrieveByIdentityResponse.ID
		}
		authReq := &magistrala.AuthorizeReq{
			SubjectType: authsvc.UserType,
			SubjectKind: authsvc.UsersKind,
			Subject:     id,
			Permission:  authsvc.MembershipPermission,
			ObjectType:  authsvc.PlatformType,
			Object:      authsvc.MagistralaObject,
		}
		repoCall := cRepo.On("RetrieveByIdentity", context.Background(), tc.user.Credentials.Identity).Return(tc.retrieveByIdentityResponse, tc.retrieveByIdentityErr)
		repoCall1 := cRepo.On("Save", context.Background(), mock.Anything).Return(tc.saveResponse, tc.saveErr)
		authCall := auth.On("Issue", mock.Anything, mock.Anything).Return(tc.issueResponse, tc.issueErr)
		authCall1 := policy.On("AddPolicies", mock.Anything, mock.Anything).Return(tc.addPoliciesResponse, tc.addPoliciesErr)
		authCall2 := auth.On("Authorize", mock.Anything, authReq).Return(tc.authorizeResponse, tc.authorizeErr)
		token, err := svc.OAuthCallback(context.Background(), tc.user)
		if err == nil {
			assert.Equal(t, tc.issueResponse.AccessToken, token.AccessToken)
			assert.Equal(t, tc.issueResponse.RefreshToken, token.RefreshToken)
		}
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		repoCall.Parent.AssertCalled(t, "RetrieveByIdentity", context.Background(), tc.user.Credentials.Identity)
		repoCall.Unset()
		repoCall1.Unset()
		authCall.Unset()
		authCall1.Unset()
		authCall2.Unset()
	}
}
