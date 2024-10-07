// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"

	"github.com/absmach/magistrala/pkg/apiutil"
	mgclients "github.com/absmach/magistrala/pkg/clients"
	"github.com/absmach/magistrala/pkg/errors"
	"github.com/absmach/magistrala/users"
	"github.com/go-kit/kit/endpoint"
)

func registrationEndpoint(svc users.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(createUserReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		user, err := svc.RegisterUser(ctx, req.token, req.user)
		if err != nil {
			return nil, err
		}

		return createUserRes{
			User:    user,
			created: true,
		}, nil
	}
}

func viewUserEndpoint(svc users.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(viewUserReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		user, err := svc.ViewUser(ctx, req.token, req.id)
		if err != nil {
			return nil, err
		}

		return viewUserRes{User: user}, nil
	}
}

func viewProfileEndpoint(svc users.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(viewProfileReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		user, err := svc.ViewProfile(ctx, req.token)
		if err != nil {
			return nil, err
		}

		return viewUserRes{User: user}, nil
	}
}

func viewUserByUserNameEndpoint(svc users.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(viewUserByUserNameReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		user, err := svc.ViewUserByUserName(ctx, req.token, req.userName)
		if err != nil {
			return nil, err
		}

		return viewUserRes{User: user}, nil
	}
}

func listUsersEndpoint(svc users.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(listUsersReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		pm := mgclients.Page{
			Status:   req.status,
			Offset:   req.offset,
			Limit:    req.limit,
			Name:     req.name,
			Tag:      req.tag,
			Metadata: req.metadata,
			Identity: req.identity,
			Order:    req.order,
			Dir:      req.dir,
			Id:       req.id,
		}
		page, err := svc.ListUsers(ctx, req.token, pm)
		if err != nil {
			return nil, err
		}

		res := usersPageRes{
			pageRes: pageRes{
				Total:  page.Total,
				Offset: page.Offset,
				Limit:  page.Limit,
			},
			Users: []viewUserRes{},
		}
		for _, user := range page.Users {
			res.Users = append(res.Users, viewUserRes{User: user})
		}

		return res, nil
	}
}

func searchUsersEndpoint(svc users.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(searchUsersReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		pm := mgclients.Page{
			Offset: req.Offset,
			Limit:  req.Limit,
			Name:   req.Name,
			Id:     req.Id,
			Order:  req.Order,
			Dir:    req.Dir,
		}
		page, err := svc.SearchUsers(ctx, req.token, pm)
		if err != nil {
			return nil, err
		}

		res := usersPageRes{
			pageRes: pageRes{
				Total:  page.Total,
				Offset: page.Offset,
				Limit:  page.Limit,
			},
			Users: []viewUserRes{},
		}
		for _, user := range page.Users {
			res.Users = append(res.Users, viewUserRes{User: user})
		}

		return res, nil
	}
}

func listMembersByGroupEndpoint(svc users.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(listMembersByObjectReq)
		req.objectKind = "groups"
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		page, err := svc.ListMembers(ctx, req.token, req.objectKind, req.objectID, req.Page)
		if err != nil {
			return nil, err
		}

		return buildUsersResponse(page), nil
	}
}

func listMembersByChannelEndpoint(svc users.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(listMembersByObjectReq)
		// In spiceDB schema, using the same 'group' type for both channels and groups, rather than having a separate type for channels.
		req.objectKind = "groups"
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		page, err := svc.ListMembers(ctx, req.token, req.objectKind, req.objectID, req.Page)
		if err != nil {
			return nil, err
		}

		return buildUsersResponse(page), nil
	}
}

func listMembersByThingEndpoint(svc users.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(listMembersByObjectReq)
		req.objectKind = "things"
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		page, err := svc.ListMembers(ctx, req.token, req.objectKind, req.objectID, req.Page)
		if err != nil {
			return nil, err
		}

		return buildUsersResponse(page), nil
	}
}

func listMembersByDomainEndpoint(svc users.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(listMembersByObjectReq)
		req.objectKind = "domains"
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		page, err := svc.ListMembers(ctx, req.token, req.objectKind, req.objectID, req.Page)
		if err != nil {
			return nil, err
		}

		return buildUsersResponse(page), nil
	}
}

func updateUserEndpoint(svc users.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateUserReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		user := users.User{
			ID:       req.id,
			Name:     req.Name,
			Metadata: req.Metadata,
		}
		user, err := svc.UpdateUser(ctx, req.token, user)
		if err != nil {
			return nil, err
		}

		return updateUserRes{User: user}, nil
	}
}

func updateUserTagsEndpoint(svc users.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateUserTagsReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		user := users.User{
			ID:   req.id,
			Tags: req.Tags,
		}
		user, err := svc.UpdateUserTags(ctx, req.token, user)
		if err != nil {
			return nil, err
		}

		return updateUserRes{User: user}, nil
	}
}

func updateUserIdentityEndpoint(svc users.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateUserIdentityReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		user, err := svc.UpdateUserIdentity(ctx, req.token, req.id, req.Identity)
		if err != nil {
			return nil, err
		}

		return updateUserRes{User: user}, nil
	}
}

// Password reset request endpoint.
// When successful password reset link is generated.
// Link is generated using MG_TOKEN_RESET_ENDPOINT env.
// and value from Referer header for host.
// {Referer}+{MG_TOKEN_RESET_ENDPOINT}+{token=TOKEN}
// http://magistrala.com/reset-request?token=xxxxxxxxxxx.
// Email with a link is being sent to the user.
// When user clicks on a link it should get the ui with form to
// enter new password, when form is submitted token and new password
// must be sent as PUT request to 'password/reset' passwordResetEndpoint.
func passwordResetRequestEndpoint(svc users.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(passwResetReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		if err := svc.GenerateResetToken(ctx, req.Email, req.Host); err != nil {
			return nil, err
		}

		return passwResetReqRes{Msg: MailSent}, nil
	}
}

// This is endpoint that actually sets new password in password reset flow.
// When user clicks on a link in email finally ends on this endpoint as explained in
// the comment above.
func passwordResetEndpoint(svc users.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(resetTokenReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		if err := svc.ResetSecret(ctx, req.Token, req.Password); err != nil {
			return nil, err
		}

		return passwChangeRes{}, nil
	}
}

func updateUserSecretEndpoint(svc users.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateUserSecretReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		user, err := svc.UpdateUserSecret(ctx, req.token, req.OldSecret, req.NewSecret)
		if err != nil {
			return nil, err
		}

		return updateUserRes{User: user}, nil
	}
}

func updateUserNamesEndpoint(svc users.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateUserNamesReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		user, err := svc.UpdateUserNames(ctx, req.token, req.User)
		if err != nil {
			return nil, err
		}

		return updateUserRes{User: user}, nil
	}
}

func updateProfilePictureEndpoint(svc users.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateProfilePictureReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		user := users.User{
			ID:             req.id,
			ProfilePicture: req.ProfilePicture,
		}

		user, err := svc.UpdateProfilePicture(ctx, req.token, user)
		if err != nil {
			return nil, err
		}

		return updateUserRes{User: user}, nil
	}
}

func updateUserRoleEndpoint(svc users.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateUserRoleReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		user := users.User{
			ID:   req.id,
			Role: req.role,
		}
		user, err := svc.UpdateUserRole(ctx, req.token, user)
		if err != nil {
			return nil, err
		}

		return updateUserRes{User: user}, nil
	}
}

func issueTokenEndpoint(svc users.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(loginUserReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		token, err := svc.IssueToken(ctx, req.Identity, req.Secret, req.DomainID)
		if err != nil {
			return nil, err
		}

		return tokenRes{
			AccessToken:  token.GetAccessToken(),
			RefreshToken: token.GetRefreshToken(),
			AccessType:   token.GetAccessType(),
		}, nil
	}
}

func refreshTokenEndpoint(svc users.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(tokenReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		token, err := svc.RefreshToken(ctx, req.RefreshToken, req.DomainID)
		if err != nil {
			return nil, err
		}

		return tokenRes{
			AccessToken:  token.GetAccessToken(),
			RefreshToken: token.GetRefreshToken(),
			AccessType:   token.GetAccessType(),
		}, nil
	}
}

func enableUserEndpoint(svc users.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(changeUserStatusReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		user, err := svc.EnableUser(ctx, req.token, req.id)
		if err != nil {
			return nil, err
		}

		return changeUserStatusRes{User: user}, nil
	}
}

func disableUserEndpoint(svc users.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(changeUserStatusReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		user, err := svc.DisableUser(ctx, req.token, req.id)
		if err != nil {
			return nil, err
		}

		return changeUserStatusRes{User: user}, nil
	}
}

func deleteUserEndpoint(svc users.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(changeUserStatusReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		if err := svc.DeleteUser(ctx, req.token, req.id); err != nil {
			return nil, err
		}

		return deleteUserRes{true}, nil
	}
}

func buildUsersResponse(cp users.MembersPage) usersPageRes {
	res := usersPageRes{
		pageRes: pageRes{
			Total:  cp.Total,
			Offset: cp.Offset,
			Limit:  cp.Limit,
		},
		Users: []viewUserRes{},
	}

	for _, user := range cp.Members {
		res.Users = append(res.Users, viewUserRes{User: user})
	}

	return res
}
