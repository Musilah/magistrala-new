// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package users

import (
	"context"
	"fmt"
	"time"

	"github.com/absmach/magistrala"
	"github.com/absmach/magistrala/auth"
	grpcclient "github.com/absmach/magistrala/auth/api/grpc"
	mgclients "github.com/absmach/magistrala/pkg/clients"
	"github.com/absmach/magistrala/pkg/errors"
	repoerr "github.com/absmach/magistrala/pkg/errors/repository"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	"golang.org/x/sync/errgroup"
)

var (
	errIssueToken            = errors.New("failed to issue token")
	errFailedPermissionsList = errors.New("failed to list permissions")
	errRecoveryToken         = errors.New("failed to generate password recovery token")
	errLoginDisableUser      = errors.New("failed to login in disabled user")
)

type service struct {
	users        Repository
	idProvider   magistrala.IDProvider
	auth         grpcclient.AuthServiceClient
	policy       magistrala.PolicyServiceClient
	hasher       Hasher
	email        Emailer
	selfRegister bool
}

// NewService returns a new Users service implementation.
func NewService(urepo Repository, authClient grpcclient.AuthServiceClient, policyClient magistrala.PolicyServiceClient, emailer Emailer, hasher Hasher, idp magistrala.IDProvider, selfRegister bool) Service {
	return service{
		users:        urepo,
		auth:         authClient,
		policy:       policyClient,
		hasher:       hasher,
		email:        emailer,
		idProvider:   idp,
		selfRegister: selfRegister,
	}
}

func (svc service) RegisterUser(ctx context.Context, token string, u User) (uc User, err error) {
	if !svc.selfRegister {
		userID, err := svc.Identify(ctx, token)
		if err != nil {
			return User{}, err
		}
		if err := svc.checkSuperAdmin(ctx, userID); err != nil {
			return User{}, err
		}
	}

	userID, err := svc.idProvider.ID()
	if err != nil {
		return User{}, err
	}

	if u.FirstName != "" || u.LastName != "" {
		u.Name = fmt.Sprintf("%s %s", u.FirstName, u.LastName)
	}

	if u.Credentials.Secret != "" {
		hash, err := svc.hasher.Hash(u.Credentials.Secret)
		if err != nil {
			return User{}, errors.Wrap(svcerr.ErrMalformedEntity, err)
		}
		u.Credentials.Secret = hash
	}

	if u.Status != mgclients.DisabledStatus && u.Status != mgclients.EnabledStatus {
		return User{}, errors.Wrap(svcerr.ErrMalformedEntity, svcerr.ErrInvalidStatus)
	}
	if u.Role != mgclients.UserRole && u.Role != mgclients.AdminRole {
		return User{}, errors.Wrap(svcerr.ErrMalformedEntity, svcerr.ErrInvalidRole)
	}
	u.ID = userID
	u.CreatedAt = time.Now()

	if err := svc.addUserPolicy(ctx, u.ID, u.Role); err != nil {
		return User{}, err
	}
	defer func() {
		if err != nil {
			if errRollback := svc.addUserPolicyRollback(ctx, u.ID, u.Role); errRollback != nil {
				err = errors.Wrap(errors.Wrap(errors.ErrRollbackTx, errRollback), err)
			}
		}
	}()
	user, err := svc.users.Save(ctx, u)
	if err != nil {
		return User{}, errors.Wrap(svcerr.ErrCreateEntity, err)
	}
	return user, nil
}

func (svc service) IssueToken(ctx context.Context, identity, secret, domainID string) (*magistrala.Token, error) {
	dbUser, err := svc.users.RetrieveByIdentity(ctx, identity)
	if err != nil {
		return &magistrala.Token{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}
	if err := svc.hasher.Compare(secret, dbUser.Credentials.Secret); err != nil {
		return &magistrala.Token{}, errors.Wrap(svcerr.ErrLogin, err)
	}

	var d string
	if domainID != "" {
		d = domainID
	}

	token, err := svc.auth.Issue(ctx, &magistrala.IssueReq{UserId: dbUser.ID, DomainId: &d, Type: uint32(auth.AccessKey)})
	if err != nil {
		return &magistrala.Token{}, errors.Wrap(errIssueToken, err)
	}

	return token, err
}

func (svc service) RefreshToken(ctx context.Context, refreshToken, domainID string) (*magistrala.Token, error) {
	var d string
	if domainID != "" {
		d = domainID
	}

	tokenUserID, err := svc.Identify(ctx, refreshToken)
	if err != nil {
		return &magistrala.Token{}, err
	}

	dbUser, err := svc.users.RetrieveByID(ctx, tokenUserID)
	if err != nil {
		return &magistrala.Token{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}
	if dbUser.Status == mgclients.DisabledStatus {
		return &magistrala.Token{}, errors.Wrap(svcerr.ErrAuthentication, errLoginDisableUser)
	}

	return svc.auth.Refresh(ctx, &magistrala.RefreshReq{RefreshToken: refreshToken, DomainId: &d})
}

func (svc service) ViewUser(ctx context.Context, token, id string) (User, error) {
	tokenUserID, err := svc.Identify(ctx, token)
	if err != nil {
		return User{}, err
	}

	user, err := svc.users.RetrieveByID(ctx, id)
	if err != nil {
		return User{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}

	if tokenUserID != id {
		if err := svc.checkSuperAdmin(ctx, tokenUserID); err != nil {
			return User{Name: user.Name, ID: user.ID}, nil
		}
	}

	user.Credentials.Secret = ""

	return user, nil
}

func (svc service) ViewProfile(ctx context.Context, token string) (User, error) {
	id, err := svc.Identify(ctx, token)
	if err != nil {
		return User{}, err
	}
	user, err := svc.users.RetrieveByID(ctx, id)
	if err != nil {
		return User{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	user.Credentials.Secret = ""

	return user, nil
}

func (svc service) ViewUserByUserName(ctx context.Context, token, userName string) (User, error) {
	_, err := svc.Identify(ctx, token)
	if err != nil {
		return User{}, err
	}

	user, err := svc.users.RetrieveByUserName(ctx, userName)
	if err != nil {
		return User{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	return user, nil
}

func (svc service) ListUsers(ctx context.Context, token string, pm mgclients.Page) (UsersPage, error) {
	userID, err := svc.Identify(ctx, token)
	if err != nil {
		return UsersPage{}, err
	}
	if err := svc.checkSuperAdmin(ctx, userID); err != nil {
		return UsersPage{}, err
	}

	pm.Role = mgclients.AllRole
	pg, err := svc.users.RetrieveAll(ctx, pm)
	if err != nil {
		return UsersPage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	return pg, err
}

func (svc service) SearchUsers(ctx context.Context, token string, pm mgclients.Page) (UsersPage, error) {
	_, err := svc.Identify(ctx, token)
	if err != nil {
		return UsersPage{}, err
	}

	page := mgclients.Page{
		Offset: pm.Offset,
		Limit:  pm.Limit,
		Name:   pm.Name,
		Id:     pm.Id,
		Role:   mgclients.UserRole,
	}

	cp, err := svc.users.SearchUsers(ctx, page)
	if err != nil {
		return UsersPage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}

	return cp, nil
}

func (svc service) UpdateUser(ctx context.Context, token string, usr User) (User, error) {
	tokenUserID, err := svc.Identify(ctx, token)
	if err != nil {
		return User{}, err
	}

	if tokenUserID != usr.ID {
		if err := svc.checkSuperAdmin(ctx, tokenUserID); err != nil {
			return User{}, err
		}
	}

	user := User{
		ID:        usr.ID,
		Name:      usr.Name,
		Metadata:  usr.Metadata,
		UpdatedAt: time.Now(),
		UpdatedBy: tokenUserID,
	}

	user, err = svc.users.Update(ctx, user)
	if err != nil {
		return User{}, errors.Wrap(svcerr.ErrUpdateEntity, err)
	}
	return user, nil
}

func (svc service) UpdateUserTags(ctx context.Context, token string, usr User) (User, error) {
	tokenUserID, err := svc.Identify(ctx, token)
	if err != nil {
		return User{}, err
	}

	if tokenUserID != usr.ID {
		if err := svc.checkSuperAdmin(ctx, tokenUserID); err != nil {
			return User{}, err
		}
	}

	user := User{
		ID:        usr.ID,
		Tags:      usr.Tags,
		UpdatedAt: time.Now(),
		UpdatedBy: tokenUserID,
	}
	user, err = svc.users.UpdateTags(ctx, user)
	if err != nil {
		return User{}, errors.Wrap(svcerr.ErrUpdateEntity, err)
	}

	return user, nil
}

func (svc service) UpdateUserIdentity(ctx context.Context, token, userID, identity string) (User, error) {
	tokenUserID, err := svc.Identify(ctx, token)
	if err != nil {
		return User{}, err
	}

	if tokenUserID != userID {
		if err := svc.checkSuperAdmin(ctx, tokenUserID); err != nil {
			return User{}, err
		}
	}

	usr := User{
		ID: userID,
		Credentials: Credentials{
			Identity: identity,
		},
		UpdatedAt: time.Now(),
		UpdatedBy: tokenUserID,
	}
	usr, err = svc.users.UpdateIdentity(ctx, usr)
	if err != nil {
		return User{}, errors.Wrap(svcerr.ErrUpdateEntity, err)
	}
	return usr, nil
}

func (svc service) GenerateResetToken(ctx context.Context, email, host string) error {
	user, err := svc.users.RetrieveByIdentity(ctx, email)
	if err != nil {
		return errors.Wrap(svcerr.ErrViewEntity, err)
	}
	issueReq := &magistrala.IssueReq{
		UserId: user.ID,
		Type:   uint32(auth.RecoveryKey),
	}
	token, err := svc.auth.Issue(ctx, issueReq)
	if err != nil {
		return errors.Wrap(errRecoveryToken, err)
	}

	return svc.SendPasswordReset(ctx, host, email, user.Name, token.AccessToken)
}

func (svc service) ResetSecret(ctx context.Context, resetToken, secret string) error {
	id, err := svc.Identify(ctx, resetToken)
	if err != nil {
		return err
	}
	u, err := svc.users.RetrieveByID(ctx, id)
	if err != nil {
		return errors.Wrap(svcerr.ErrViewEntity, err)
	}

	secret, err = svc.hasher.Hash(secret)
	if err != nil {
		return errors.Wrap(svcerr.ErrMalformedEntity, err)
	}
	u = User{
		ID: u.ID,
		Credentials: Credentials{
			Identity: u.Credentials.Identity,
			Secret:   secret,
		},
		UpdatedAt: time.Now(),
		UpdatedBy: id,
	}
	if _, err := svc.users.UpdateSecret(ctx, u); err != nil {
		return errors.Wrap(svcerr.ErrAuthorization, err)
	}
	return nil
}

func (svc service) UpdateUserSecret(ctx context.Context, token, oldSecret, newSecret string) (User, error) {
	id, err := svc.Identify(ctx, token)
	if err != nil {
		return User{}, err
	}
	dbUser, err := svc.users.RetrieveByID(ctx, id)
	if err != nil {
		return User{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	if _, err := svc.IssueToken(ctx, dbUser.Credentials.Identity, oldSecret, ""); err != nil {
		return User{}, err
	}
	newSecret, err = svc.hasher.Hash(newSecret)
	if err != nil {
		return User{}, errors.Wrap(svcerr.ErrMalformedEntity, err)
	}
	dbUser.Credentials.Secret = newSecret
	dbUser.UpdatedAt = time.Now()
	dbUser.UpdatedBy = id

	dbUser, err = svc.users.UpdateSecret(ctx, dbUser)
	if err != nil {
		return User{}, errors.Wrap(svcerr.ErrUpdateEntity, err)
	}

	return dbUser, nil
}

func (svc service) UpdateUserNames(ctx context.Context, token string, usr User) (User, error) {
	tokenUserID, err := svc.Identify(ctx, token)
	if err != nil {
		return User{}, err
	}

	if tokenUserID != usr.ID {
		if err := svc.checkSuperAdmin(ctx, tokenUserID); err != nil {
			return User{}, err
		}
	}

	if usr.FirstName == "" || usr.LastName == "" {
		return User{}, errors.Wrap(svcerr.ErrMalformedEntity, svcerr.ErrMissingNames)
	}

	usr.Name = fmt.Sprintf("%s %s", usr.FirstName, usr.LastName)
	usr.UpdatedAt = time.Now()
	usr.UpdatedBy = tokenUserID

	updatedUser, err := svc.users.UpdateUserNames(ctx, usr)
	if err != nil {
		return User{}, errors.Wrap(svcerr.ErrUpdateEntity, err)
	}
	return updatedUser, nil
}

func (svc service) UpdateProfilePicture(ctx context.Context, token string, usr User) (User, error) {
	tokenUserID, err := svc.Identify(ctx, token)
	if err != nil {
		return User{}, err
	}

	if tokenUserID != usr.ID {
		if err := svc.checkSuperAdmin(ctx, tokenUserID); err != nil {
			return User{}, err
		}
	}

	if usr.ProfilePicture == "" {
		return User{}, errors.Wrap(svcerr.ErrMalformedEntity, svcerr.ErrMissingProfilePicture)
	}

	usr.UpdatedAt = time.Now()
	usr.UpdatedBy = tokenUserID

	updatedUser, err := svc.users.UpdateProfilePicture(ctx, usr)
	if err != nil {
		return User{}, errors.Wrap(svcerr.ErrUpdateEntity, err)
	}
	return updatedUser, nil
}

func (svc service) SendPasswordReset(_ context.Context, host, email, user, token string) error {
	to := []string{email}
	return svc.email.SendPasswordReset(to, host, user, token)
}

func (svc service) UpdateUserRole(ctx context.Context, token string, usr User) (User, error) {
	tokenUserID, err := svc.Identify(ctx, token)
	if err != nil {
		return User{}, err
	}

	if err := svc.checkSuperAdmin(ctx, tokenUserID); err != nil {
		return User{}, err
	}
	user := User{
		ID:        usr.ID,
		Role:      usr.Role,
		UpdatedAt: time.Now(),
		UpdatedBy: tokenUserID,
	}

	if _, err := svc.authorize(ctx, auth.UserType, auth.UsersKind, user.ID, auth.MembershipPermission, auth.PlatformType, auth.MagistralaObject); err != nil {
		return User{}, err
	}

	if err := svc.updateUserPolicy(ctx, usr.ID, usr.Role); err != nil {
		return User{}, err
	}

	user, err = svc.users.UpdateRole(ctx, user)
	if err != nil {
		// If failed to update role in DB, then revert back to platform admin policy in spicedb
		if errRollback := svc.updateUserPolicy(ctx, usr.ID, mgclients.UserRole); errRollback != nil {
			return User{}, errors.Wrap(errRollback, err)
		}
		return User{}, errors.Wrap(svcerr.ErrUpdateEntity, err)
	}
	return user, nil
}

func (svc service) EnableUser(ctx context.Context, token, id string) (User, error) {
	user := User{
		ID:        id,
		UpdatedAt: time.Now(),
		Status:    mgclients.EnabledStatus,
	}
	user, err := svc.changeUserStatus(ctx, token, user)
	if err != nil {
		return User{}, errors.Wrap(mgclients.ErrEnableClient, err)
	}

	return user, nil
}

func (svc service) DisableUser(ctx context.Context, token, id string) (User, error) {
	user := User{
		ID:        id,
		UpdatedAt: time.Now(),
		Status:    mgclients.DisabledStatus,
	}
	user, err := svc.changeUserStatus(ctx, token, user)
	if err != nil {
		return User{}, err
	}

	return user, nil
}

func (svc service) changeUserStatus(ctx context.Context, token string, user User) (User, error) {
	tokenUserID, err := svc.Identify(ctx, token)
	if err != nil {
		return User{}, err
	}
	if tokenUserID != user.ID {
		if err := svc.checkSuperAdmin(ctx, tokenUserID); err != nil {
			return User{}, err
		}
	}
	dbUser, err := svc.users.RetrieveByID(ctx, user.ID)
	if err != nil {
		return User{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	if dbUser.Status == user.Status {
		return User{}, errors.ErrStatusAlreadyAssigned
	}
	user.UpdatedBy = tokenUserID

	user, err = svc.users.ChangeStatus(ctx, user)
	if err != nil {
		return User{}, errors.Wrap(svcerr.ErrUpdateEntity, err)
	}
	return user, nil
}

func (svc service) DeleteUser(ctx context.Context, token, id string) error {
	user := User{
		ID:        id,
		UpdatedAt: time.Now(),
		Status:    mgclients.DeletedStatus,
	}

	if _, err := svc.changeUserStatus(ctx, token, user); err != nil {
		return err
	}

	return nil
}

func (svc service) ListMembers(ctx context.Context, token, objectKind, objectID string, pm mgclients.Page) (MembersPage, error) {
	res, err := svc.identify(ctx, token)
	if err != nil {
		return MembersPage{}, err
	}
	var objectType string
	var authzPerm string
	switch objectKind {
	case auth.ThingsKind:
		objectType = auth.ThingType
		authzPerm = pm.Permission
	case auth.DomainsKind:
		objectType = auth.DomainType
		authzPerm = auth.SwitchToPermission(pm.Permission)
	case auth.GroupsKind:
		fallthrough
	default:
		objectType = auth.GroupType
		authzPerm = auth.SwitchToPermission(pm.Permission)
	}

	if _, err := svc.authorize(ctx, auth.UserType, auth.TokenKind, token, authzPerm, objectType, objectID); err != nil {
		return MembersPage{}, errors.Wrap(svcerr.ErrAuthorization, err)
	}
	duids, err := svc.policy.ListAllSubjects(ctx, &magistrala.ListSubjectsReq{
		SubjectType: auth.UserType,
		Permission:  pm.Permission,
		Object:      objectID,
		ObjectType:  objectType,
	})
	if err != nil {
		return MembersPage{}, errors.Wrap(svcerr.ErrNotFound, err)
	}
	if len(duids.Policies) == 0 {
		return MembersPage{
			Page: mgclients.Page{Total: 0, Offset: pm.Offset, Limit: pm.Limit},
		}, nil
	}

	var userIDs []string

	for _, domainUserID := range duids.Policies {
		_, userID := auth.DecodeDomainUserID(domainUserID)
		userIDs = append(userIDs, userID)
	}
	pm.IDs = userIDs

	up, err := svc.users.RetrieveAll(ctx, pm)
	if err != nil {
		return MembersPage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}

	for i, u := range up.Users {
		up.Users[i] = User{
			ID:        u.ID,
			Name:      u.Name,
			CreatedAt: u.CreatedAt,
			UpdatedAt: u.UpdatedAt,
			Status:    u.Status,
		}
	}

	if pm.ListPerms && len(up.Users) > 0 {
		g, ctx := errgroup.WithContext(ctx)

		for i := range up.Users {
			// Copying loop variable "i" to avoid "loop variable captured by func literal"
			iter := i
			g.Go(func() error {
				return svc.retrieveObjectUsersPermissions(ctx, res.GetDomainId(), objectType, objectID, &up.Users[iter])
			})
		}

		if err := g.Wait(); err != nil {
			return MembersPage{}, err
		}
	}

	return MembersPage{
		Page:    up.Page,
		Members: up.Users,
	}, nil
}

func (svc service) retrieveObjectUsersPermissions(ctx context.Context, domainID, objectType, objectID string, user *User) error {
	userID := auth.EncodeDomainUserID(domainID, user.ID)
	permissions, err := svc.listObjectUserPermission(ctx, userID, objectType, objectID)
	if err != nil {
		return errors.Wrap(svcerr.ErrAuthorization, err)
	}
	user.Permissions = permissions
	return nil
}

func (svc service) listObjectUserPermission(ctx context.Context, userID, objectType, objectID string) ([]string, error) {
	lp, err := svc.policy.ListPermissions(ctx, &magistrala.ListPermissionsReq{
		SubjectType: auth.UserType,
		Subject:     userID,
		Object:      objectID,
		ObjectType:  objectType,
	})
	if err != nil {
		return []string{}, errors.Wrap(errFailedPermissionsList, err)
	}
	return lp.GetPermissions(), nil
}

func (svc *service) checkSuperAdmin(ctx context.Context, adminID string) error {
	if _, err := svc.authorize(ctx, auth.UserType, auth.UsersKind, adminID, auth.AdminPermission, auth.PlatformType, auth.MagistralaObject); err != nil {
		if err := svc.users.CheckSuperAdmin(ctx, adminID); err != nil {
			return errors.Wrap(svcerr.ErrAuthorization, err)
		}
		return errors.Wrap(svcerr.ErrAuthorization, err)
	}

	return nil
}

func (svc service) identify(ctx context.Context, token string) (*magistrala.IdentityRes, error) {
	res, err := svc.auth.Identify(ctx, &magistrala.IdentityReq{Token: token})
	if err != nil {
		return &magistrala.IdentityRes{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}
	return res, nil
}

func (svc *service) authorize(ctx context.Context, subjType, subjKind, subj, perm, objType, obj string) (string, error) {
	req := &magistrala.AuthorizeReq{
		SubjectType: subjType,
		SubjectKind: subjKind,
		Subject:     subj,
		Permission:  perm,
		ObjectType:  objType,
		Object:      obj,
	}
	res, err := svc.auth.Authorize(ctx, req)
	if err != nil {
		return "", errors.Wrap(svcerr.ErrAuthorization, err)
	}

	if !res.GetAuthorized() {
		return "", svcerr.ErrAuthorization
	}
	return res.GetId(), nil
}

func (svc service) OAuthCallback(ctx context.Context, user User) (*magistrala.Token, error) {
	ruser, err := svc.users.RetrieveByIdentity(ctx, user.Credentials.Identity)
	if err != nil {
		switch errors.Contains(err, repoerr.ErrNotFound) {
		case true:
			ruser, err = svc.RegisterUser(ctx, "", user)
			if err != nil {
				return &magistrala.Token{}, err
			}
		default:
			return &magistrala.Token{}, err
		}
	}

	if _, err = svc.authorize(ctx, auth.UserType, auth.UsersKind, ruser.ID, auth.MembershipPermission, auth.PlatformType, auth.MagistralaObject); err != nil {
		if err := svc.addUserPolicy(ctx, ruser.ID, ruser.Role); err != nil {
			return &magistrala.Token{}, err
		}
	}

	claims := &magistrala.IssueReq{
		UserId: ruser.ID,
		Type:   uint32(auth.AccessKey),
	}

	return svc.auth.Issue(ctx, claims)
}

func (svc service) Identify(ctx context.Context, token string) (string, error) {
	user, err := svc.auth.Identify(ctx, &magistrala.IdentityReq{Token: token})
	if err != nil {
		return "", errors.Wrap(svcerr.ErrAuthentication, err)
	}
	return user.GetUserId(), nil
}

func (svc service) addUserPolicy(ctx context.Context, userID string, role mgclients.Role) error {
	var policies magistrala.AddPoliciesReq

	policies.AddPoliciesReq = append(policies.AddPoliciesReq, &magistrala.AddPolicyReq{
		SubjectType: auth.UserType,
		Subject:     userID,
		Relation:    auth.MemberRelation,
		ObjectType:  auth.PlatformType,
		Object:      auth.MagistralaObject,
	})

	if role == mgclients.AdminRole {
		policies.AddPoliciesReq = append(policies.AddPoliciesReq, &magistrala.AddPolicyReq{
			SubjectType: auth.UserType,
			Subject:     userID,
			Relation:    auth.AdministratorRelation,
			ObjectType:  auth.PlatformType,
			Object:      auth.MagistralaObject,
		})
	}
	resp, err := svc.policy.AddPolicies(ctx, &policies)
	if err != nil {
		return errors.Wrap(svcerr.ErrAddPolicies, err)
	}
	if !resp.Added {
		return svcerr.ErrAuthorization
	}
	return nil
}

func (svc service) addUserPolicyRollback(ctx context.Context, userID string, role mgclients.Role) error {
	var policies magistrala.DeletePoliciesReq

	policies.DeletePoliciesReq = append(policies.DeletePoliciesReq, &magistrala.DeletePolicyReq{
		SubjectType: auth.UserType,
		Subject:     userID,
		Relation:    auth.MemberRelation,
		ObjectType:  auth.PlatformType,
		Object:      auth.MagistralaObject,
	})

	if role == mgclients.AdminRole {
		policies.DeletePoliciesReq = append(policies.DeletePoliciesReq, &magistrala.DeletePolicyReq{
			SubjectType: auth.UserType,
			Subject:     userID,
			Relation:    auth.AdministratorRelation,
			ObjectType:  auth.PlatformType,
			Object:      auth.MagistralaObject,
		})
	}
	resp, err := svc.policy.DeletePolicies(ctx, &policies)
	if err != nil {
		return errors.Wrap(svcerr.ErrDeletePolicies, err)
	}
	if !resp.Deleted {
		return svcerr.ErrAuthorization
	}
	return nil
}

func (svc service) updateUserPolicy(ctx context.Context, userID string, role mgclients.Role) error {
	switch role {
	case mgclients.AdminRole:
		resp, err := svc.policy.AddPolicy(ctx, &magistrala.AddPolicyReq{
			SubjectType: auth.UserType,
			Subject:     userID,
			Relation:    auth.AdministratorRelation,
			ObjectType:  auth.PlatformType,
			Object:      auth.MagistralaObject,
		})
		if err != nil {
			return errors.Wrap(svcerr.ErrAddPolicies, err)
		}
		if !resp.Added {
			return svcerr.ErrAuthorization
		}
		return nil
	case mgclients.UserRole:
		fallthrough
	default:
		resp, err := svc.policy.DeletePolicyFilter(ctx, &magistrala.DeletePolicyFilterReq{
			SubjectType: auth.UserType,
			Subject:     userID,
			Relation:    auth.AdministratorRelation,
			ObjectType:  auth.PlatformType,
			Object:      auth.MagistralaObject,
		})
		if err != nil {
			return errors.Wrap(svcerr.ErrDeletePolicies, err)
		}
		if !resp.Deleted {
			return svcerr.ErrAuthorization
		}
		return nil
	}
}
