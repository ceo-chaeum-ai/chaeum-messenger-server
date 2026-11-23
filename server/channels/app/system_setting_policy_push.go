// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import (
	"encoding/json"
	"maps"
	"net/http"
	"slices"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/mlog"
	"github.com/mattermost/mattermost/server/public/shared/request"
	"github.com/mattermost/mattermost/server/v8/einterfaces"
)

func (a *App) systemSettingPoliciesEvaluated() bool {
	return a.Srv().Channels().AccessControl != nil &&
		systemSettingPoliciesEnabled(a.Config()) &&
		model.MinimumEnterpriseAdvancedLicense(a.License())
}

func (a *App) systemSettingPoliciesForPush(rctx request.CTX) []cachedSystemSettingPolicy {
	if !a.systemSettingPoliciesEvaluated() {
		return nil
	}

	policies, err := a.Srv().Channels().systemSettingPoliciesCache.Get(rctx, a.Srv().Store().AccessControlPolicy())
	if err != nil {
		rctx.Logger().Warn("Failed to load system setting policies for override push", mlog.Err(err))
		return nil
	}
	return policies
}

// force also pushes to sessions whose role chain no policy targets, so a role
// change that moves a user out of a targeted role clears its overrides.
func (a *App) pushClientConfigOverrides(rctx request.CTX, userID, sessionID string, force bool) {
	if userID == "" || len(a.systemSettingPoliciesForPush(rctx)) == 0 {
		return
	}
	a.goPushClientConfigOverrides(userID, sessionID, force)
}

// written holds the user's values as written, and is nil when the changed fields are unknown.
// cached is the user's subject as cached before the write, or nil.
func (a *App) pushClientConfigOverridesForUserAttributes(rctx request.CTX, userID string, cached *model.Subject, written []*model.PropertyValue) {
	if userID == "" {
		return
	}
	var fieldIDs []string
	if written != nil {
		fieldIDs = make([]string, 0, len(written))
		for _, v := range written {
			fieldIDs = append(fieldIDs, v.FieldID)
		}
	}
	policies := a.systemSettingPoliciesForPush(rctx)
	if !slices.ContainsFunc(policies, func(p cachedSystemSettingPolicy) bool {
		return fieldIDs == nil || p.referencesField(fieldIDs)
	}) {
		return
	}
	if written != nil {
		a.cacheWrittenUserSubject(rctx, userID, cached, written)
	}
	a.goPushClientConfigOverrides(userID, "", false)
}

// cacheWrittenUserSubject caches the user's subject as the attribute view will read once it
// is refreshed: the cached subject, or else the view's current row, with the values just
// written projected and merged over it. The push then evaluates that subject instead of
// refreshing the view, and a later write merges over this one. Run before the push, and
// synchronously, so successive writes merge in order.
//
// The projection must match UserAttributeView's (migration 000223) for every field type, so
// it changes with the view. A written value it can't project leaves the user uncached, and the
// push reads the view as any evaluation does.
func (a *App) cacheWrittenUserSubject(rctx request.CTX, userID string, cached *model.Subject, written []*model.PropertyValue) {
	group, err := a.Srv().propertyService.Group(model.AccessControlPropertyGroupName)
	if err != nil {
		rctx.Logger().Warn("Failed to load the access control property group for an override push", mlog.Err(err))
		return
	}
	fields, err := a.Srv().Store().PropertyField().GetForGroup(rctx, group.ID)
	if err != nil {
		rctx.Logger().Warn("Failed to load attribute fields for an override push", mlog.String("user_id", userID), mlog.Err(err))
		return
	}
	fieldsByID := make(map[string]*model.PropertyField, len(fields))
	for _, f := range fields {
		fieldsByID[f.ID] = f
	}

	type projection struct {
		value   any
		deleted bool
	}
	projected := make(map[string]projection, len(written))
	for _, v := range written {
		if v.GroupID != group.ID {
			continue
		}
		field, ok := fieldsByID[v.FieldID]
		if !ok || model.PropertyFieldOptionsOmitted(field.Attrs) {
			return
		}
		if field.ObjectType != model.PropertyFieldObjectTypeUser {
			continue
		}
		if v.DeleteAt != 0 {
			projected[field.Name] = projection{deleted: true}
			continue
		}

		var raw any
		if err := json.Unmarshal(v.Value, &raw); err != nil {
			return
		}
		// GetForGroup hydrates the live options of the field and of the template it links to,
		// which is the set the view resolves option IDs against.
		options := map[string]map[string]any{}
		list, _ := field.Attrs[model.PropertyFieldAttributeOptions].([]any)
		for _, item := range list {
			option, _ := item.(map[string]any)
			if id, ok := option["id"].(string); ok {
				if _, seen := options[id]; !seen {
					options[id] = option
				}
			}
		}
		optionIDs, isArray := raw.([]any)

		var value any
		switch {
		case field.Type == model.PropertyFieldTypeSelect || field.Type == model.PropertyFieldTypeRank:
			id, _ := raw.(string)
			option, ok := options[id]
			if !ok {
				break
			}
			if field.Type == model.PropertyFieldTypeSelect {
				value = option["name"]
			} else {
				value = map[string]any{"name": option["name"], "rank": option["rank"]}
			}
		case field.Type == model.PropertyFieldTypeMultiselect && isArray:
			var names []any
			for _, item := range optionIDs {
				id, _ := item.(string)
				if option, ok := options[id]; ok {
					names = append(names, option["name"])
				}
			}
			if len(names) > 0 {
				value = names
			}
		case field.Type == model.PropertyFieldTypeGraph:
			ids := []any{}
			for _, item := range optionIDs {
				id, _ := item.(string)
				if _, ok := options[id]; ok {
					ids = append(ids, id)
				}
			}
			value = ids
		default:
			value = raw
		}
		projected[field.Name] = projection{value: value}
	}
	if len(projected) == 0 && cached == nil {
		return
	}

	var attributes map[string]any
	if cached != nil {
		attributes = cached.Attributes
	} else {
		subject, err := a.Srv().Store().Attributes().GetSubject(rctx, userID, group.ID, model.PropertyFieldObjectTypeUser)
		if err != nil && !isNotFoundError(err) {
			rctx.Logger().Warn("Failed to read attributes for an override push", mlog.String("user_id", userID), mlog.Err(err))
			return
		}
		if subject != nil {
			attributes = subject.Attributes
		}
	}
	if attributes == nil {
		attributes = make(map[string]any, len(projected))
	}
	for name, p := range projected {
		if p.deleted {
			delete(attributes, name)
		} else {
			attributes[name] = p.value
		}
	}

	a.Srv().Store().Attributes().SetCachedUserSubject(&model.Subject{
		ID:         userID,
		Type:       model.PropertyFieldObjectTypeUser,
		Attributes: attributes,
	})
}

func (a *App) pushClientConfigOverridesForSessionAttributes(rctx request.CTX, userID, sessionID string, changed []string) {
	if userID == "" {
		return
	}
	policies := a.systemSettingPoliciesForPush(rctx)
	if !slices.ContainsFunc(policies, func(p cachedSystemSettingPolicy) bool {
		return p.referencesSessionAttribute(changed)
	}) {
		return
	}
	a.goPushClientConfigOverrides(userID, sessionID, false)
}

// A nil fieldIDs means the changed fields are unknown.
func (a *App) pushClientConfigOverridesForFields(rctx request.CTX, fieldIDs []string) {
	var targetRoles []string
	for _, p := range a.systemSettingPoliciesForPush(rctx) {
		if len(p.Roles) == 0 || (fieldIDs != nil && !p.referencesField(fieldIDs)) {
			continue
		}
		targetRoles = append(targetRoles, p.Roles[0])
	}
	if len(targetRoles) == 0 {
		return
	}

	slices.Sort(targetRoles)
	a.publishSystemSettingPolicyUpdate(slices.Compact(targetRoles), nil)
}

func (a *App) goPushClientConfigOverrides(userID, sessionID string, force bool) {
	a.Srv().Go(func() {
		a.pushClientConfigOverridesForUser(request.EmptyContext(a.Log()), userID, sessionID, force)
	})
}

// Overrides are evaluated on this node and sent per session, so other nodes
// never evaluate against attribute data they may not have caught up on yet.
// Sessions are read from the master because the push may follow a write a
// replica hasn't caught up on; GetSessions always reads a replica, so it only
// lists the session IDs.
func (a *App) pushClientConfigOverridesForUser(rctx request.CTX, userID, sessionID string, force bool) {
	sessionIDs := []string{sessionID}
	if sessionID == "" {
		listed, appErr := a.GetSessions(rctx, userID)
		if appErr != nil {
			rctx.Logger().Warn("Failed to load sessions for client config override push", mlog.String("user_id", userID), mlog.Err(appErr))
			return
		}
		sessionIDs = make([]string, 0, len(listed))
		for _, session := range listed {
			sessionIDs = append(sessionIDs, session.Id)
		}
	}

	masterCtx := RequestContextWithMaster(rctx)
	overridesBySession := make(map[string]map[string]string, len(sessionIDs))
	for _, id := range sessionIDs {
		session, err := a.Srv().Store().Session().Get(masterCtx, id)
		if err != nil {
			if !isNotFoundError(err) {
				rctx.Logger().Warn("Failed to load session for client config override push",
					mlog.String("user_id", userID),
					mlog.String("session_id", id),
					mlog.Err(err),
				)
			}
			continue
		}
		if session.UserId != userID || session.IsExpired() {
			continue
		}

		overrides, hasCandidate, evalErr := a.evaluateClientConfigOverrides(rctx.WithSession(session))
		if evalErr != nil {
			rctx.Logger().Warn("Failed to evaluate client config overrides for push",
				mlog.String("user_id", userID),
				mlog.String("session_id", session.Id),
				mlog.Err(evalErr),
			)
			continue
		}
		if !hasCandidate && !force {
			continue
		}
		overridesBySession[session.Id] = overrides
	}

	a.publishClientConfigOverrides(userID, overridesBySession)
}

func (a *App) publishClientConfigOverrides(userID string, overridesBySession map[string]map[string]string) {
	if len(overridesBySession) == 0 {
		return
	}

	message := model.NewWebSocketEvent(model.WebsocketEventSystemSettingPolicyUpdated, "", "", userID, nil, "")
	useSystemSettingOverridesBySessionHook(message, overridesBySession)
	a.Publish(message)
}

func (a *App) systemSettingPolicyBeforeSave(rctx request.CTX, acs einterfaces.AccessControlServiceInterface, policyID string) (policy *model.AccessControlPolicy, ok bool) {
	stored, appErr := acs.GetPolicy(rctx, policyID)
	if appErr != nil {
		if appErr.StatusCode == http.StatusNotFound {
			return nil, true
		}
		rctx.Logger().Warn("Failed to read system setting policy before save; the save will re-evaluate every connection",
			mlog.String("policy_id", policyID),
			mlog.Err(appErr),
		)
		return nil, false
	}
	return stored, true
}

// A nil targetRoles reaches every connection.
type systemSettingPolicyChange struct {
	targetRoles []string
}

// Returns nil when the save can't change any session's overrides, as for a
// rename. An unknown stored version re-evaluates every connection.
func newSystemSettingPolicyChange(stored *model.AccessControlPolicy, storedKnown bool, next *model.AccessControlPolicy) *systemSettingPolicyChange {
	if !storedKnown {
		return &systemSettingPolicyChange{}
	}

	before, after := newSystemSettingPolicyVersion(stored), newSystemSettingPolicyVersion(next)
	if before != nil && after != nil && before.role == after.role && maps.Equal(before.rules, after.rules) {
		return nil
	}

	var roles []string
	for _, version := range []*systemSettingPolicyVersion{before, after} {
		if version != nil && version.role != "" && len(version.rules) > 0 {
			roles = append(roles, version.role)
		}
	}
	if len(roles) == 0 {
		return nil
	}
	slices.Sort(roles)
	return &systemSettingPolicyChange{targetRoles: slices.Compact(roles)}
}

// Must run after the policy cache is invalidated.
func (a *App) publishSystemSettingPolicyChange(change *systemSettingPolicyChange, stored systemSettingPolicyChangeRef) {
	if change == nil {
		return
	}
	a.publishSystemSettingPolicyUpdate(change.targetRoles, &stored)
}

type systemSettingRuleVersion struct {
	expression string
	value      string
}

type systemSettingPolicyVersion struct {
	role  string
	rules map[string]systemSettingRuleVersion
}

func newSystemSettingPolicyVersion(policy *model.AccessControlPolicy) *systemSettingPolicyVersion {
	if policy == nil || policy.Type != model.AccessControlPolicyTypeSystemSetting {
		return nil
	}

	version := &systemSettingPolicyVersion{rules: make(map[string]systemSettingRuleVersion, len(policy.Rules))}
	if len(policy.Roles) > 0 {
		version.role = policy.Roles[0]
	}
	for _, rule := range policy.Rules {
		if len(rule.Actions) != 1 || rule.Expression == "" {
			continue
		}
		version.rules[rule.Actions[0]] = systemSettingRuleVersion{expression: rule.Expression, value: rule.Value}
	}
	return version
}
