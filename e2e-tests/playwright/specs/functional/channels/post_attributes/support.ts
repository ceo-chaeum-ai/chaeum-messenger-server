// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

import type {Locator, Page, Request} from '@playwright/test';
import type {Client4} from '@mattermost/client';
import type {Post} from '@mattermost/types/posts';
import type {FieldType, PropertyField, PropertyPermissionLevel} from '@mattermost/types/properties';
import type {Team} from '@mattermost/types/teams';
import type {UserProfile} from '@mattermost/types/users';

import {
    Api,
    expect,
    ignoreMissing,
    settle,
    type App,
    type generated,
    type PlaywrightExtended,
} from '@mattermost/playwright-lib';

export const GROUP = 'post_attributes';
export const OBJECT_TYPE = 'post';

// Prefix on every field these specs create, so cleanup never touches a real one.
export const FIELD_PREFIX = 'postattr_e2e';

// The values endpoint the chips must never hit. Hydration is the whole point of the
// feature: the values ride on the post, so a per-post fetch means it regressed.
export const VALUES_ROUTE = `/api/v4/properties/groups/${GROUP}/${OBJECT_TYPE}/values/`;

// The query parameter that asks a posts endpoint to hydrate.
export const HYDRATION_PARAM = `propertyGroup=${GROUP}`;

export function fieldName(suffix: string, uniqueId: string): string {
    return `${FIELD_PREFIX}_${suffix}_${uniqueId}`;
}

type CreateOptions = {
    type?: FieldType;

    // A bare string is an option with no colour. The object form carries one — any
    // string, since the server stores options as opaque maps and validates only their
    // ids, so an unrecognised token reaches the client exactly as written.
    options?: Array<string | {name: string; color: string}>;

    // Omitted means system-scoped, which applies to every channel. A channel id
    // scopes the field to that channel only, and a team id to that team's channels
    // (and so never to a direct or group message).
    channelId?: string;
    teamId?: string;

    visibility?: 'always' | 'when_set' | 'hidden';
    sortOrder?: number;

    // A text field's subtype: `channel`, `team`, `timestamp` or `post` store an id or an
    // epoch the chip resolves, and any other string is shown as plain text.
    subType?: string;

    // Who may write a value. Omitted means the server's default, which for a
    // post-object field is `member` — so a field created without this is already
    // writable by any member of the channel, and only a field that needs to render
    // as read-only has to say anything here. `none` is the one level nobody
    // satisfies, including a system admin over HTTP.
    permissionValues?: PropertyPermissionLevel;
};

/**
 * Creates one post attribute field.
 *
 * Provisioned through the API rather than the UI because there is no admin UI for
 * post attribute fields yet — and the local `/post-attributes-seed` slash command must
 * never be committed, so it cannot back an E2E spec.
 */
export async function createField(
    adminClient: Client4,
    name: string,
    {type, options = [], channelId, teamId, visibility, sortOrder, subType, permissionValues}: CreateOptions = {},
): Promise<PropertyField> {
    const attrs: Record<string, unknown> = {};

    if (options.length) {
        // The server fills in the ids; what comes back is the authority on them.
        attrs.options = options.map((option) => {
            if (typeof option === 'string') {
                return {id: '', name: option};
            }

            return {id: '', name: option.name, color: option.color};
        });
    }
    if (visibility) {
        attrs.visibility = visibility;
    }
    if (sortOrder !== undefined) {
        attrs.sort_order = sortOrder;
    }
    if (subType) {
        attrs.subType = subType;
    }

    const field: Record<string, unknown> = {
        name,
        type: type ?? (options.length ? 'select' : 'text'),
        target_type: (channelId && 'channel') || (teamId && 'team') || 'system',
        target_id: channelId ?? teamId ?? '',
        attrs,
    };

    if (permissionValues) {
        field.permission_values = permissionValues;
    }

    return adminClient.createPropertyField(GROUP, OBJECT_TYPE, field as Parameters<Client4['createPropertyField']>[2]);
}

export function optionId(field: PropertyField, name: string): string {
    const options = (field.attrs?.options ?? []) as Array<{id: string; name: string}>;
    const match = options.find((option) => option.name === name);

    if (!match) {
        throw new Error(`option ${name} not found on ${field.name}`);
    }

    return match.id;
}

/**
 * Sets a post's values. `items` holds option ids for an option-bearing field and an
 * array of them for a multiselect.
 */
export async function setPostValues(
    client: Client4,
    postId: string,
    items: Array<{field_id: string; value: unknown}>,
): Promise<void> {
    await client.patchPropertyValues(GROUP, OBJECT_TYPE, postId, items as Array<{field_id: string; value: unknown}>);
}

/**
 * Changes some of a field's attrs, keeping the rest. A patch replaces `attrs` as a whole,
 * so the field's current ones are sent back with the change applied.
 */
export async function patchFieldAttrs(
    adminClient: Client4,
    field: PropertyField,
    attrs: Record<string, unknown>,
): Promise<PropertyField> {
    return adminClient.patchPropertyField(GROUP, OBJECT_TYPE, field.id, {attrs: {...field.attrs, ...attrs}});
}

// The most options one request to the options endpoint may carry.
const OPTIONS_PER_REQUEST = 200;

/**
 * Adds options to a field through its options endpoint, as many requests as the count
 * takes. The client has no method for that endpoint, so it is called directly.
 */
export async function addFieldOptions(adminClient: Client4, field: PropertyField, names: string[]): Promise<void> {
    const route = adminClient.getPropertyFieldOptionsRoute(GROUP, OBJECT_TYPE, field.id);

    for (let start = 0; start < names.length; start += OPTIONS_PER_REQUEST) {
        const batch = names.slice(start, start + OPTIONS_PER_REQUEST).map((name) => ({name}));
        const res = await fetch(route, {
            method: 'POST',
            headers: {'Content-Type': 'application/json', Authorization: `Bearer ${adminClient.getToken()}`},
            body: JSON.stringify(batch),
        });

        if (!res.ok) {
            throw new Error(`adding options to ${field.name} failed: ${res.status} ${await res.text()}`);
        }
    }
}

/**
 * Counts full page loads after the point it is called, so "without a reload" is asserted
 * rather than assumed: a value or field that changes in place leaves the count at zero.
 */
export function countLoads(page: Page): () => number {
    let loads = 0;

    page.on('load', () => {
        loads++;
    });

    return () => loads;
}

/**
 * Creates a post the way the composer does: the values ride on the create request as
 * `metadata.property_values`, so the server writes them as the post is made and announces
 * them over the websocket, rather than a second request setting them afterwards.
 */
export async function createPostWithValues(
    client: Client4,
    channelId: string,
    message: string,
    items: SentValue[],
    {rootId, type}: {rootId?: string; type?: string} = {},
): Promise<Post> {
    return client.createPost({
        channel_id: channelId,
        message,
        root_id: rootId,
        type,
        metadata: {property_values: items},
    } as unknown as Parameters<Client4['createPost']>[0]);
}

export type MemberOptions = {
    // A guest account. The server refuses to make one while guest accounts are off.
    guest?: boolean;

    // Roles to hold on top of a plain account's.
    systemAdmin?: boolean;
    teamAdmin?: boolean;
    channelAdmin?: boolean;
};

/**
 * Creates another user, puts them on the team and in the given channels, and logs a
 * client in as them, for a case that needs a second person acting on the same posts.
 *
 * `channelAdmin` applies to every channel given. `initSetup` already makes the first
 * user and team; this is the second one, and the third.
 */
export async function addMember(
    pw: PlaywrightExtended,
    adminClient: Client4,
    team: Team,
    channelIds: string[],
    {guest, systemAdmin, teamAdmin, channelAdmin}: MemberOptions = {},
): Promise<{user: UserProfile & {password: string}; client: Client4}> {
    const user = await pw.createNewUserProfile(adminClient, {prefix: guest ? 'guest' : 'member'});

    if (guest) {
        await adminClient.demoteUserToGuest(user.id);
    }
    if (systemAdmin) {
        await adminClient.updateUserRoles(user.id, 'system_user system_admin');
    }

    await adminClient.addToTeam(team.id, user.id);

    if (teamAdmin) {
        await adminClient.updateTeamMemberSchemeRoles(team.id, user.id, true, true);
    }

    for (const channelId of channelIds) {
        await adminClient.addToChannel(user.id, channelId);
        if (channelAdmin) {
            await adminClient.updateChannelMemberRoles(channelId, user.id, 'channel_user channel_admin');
        }
    }

    const {client} = await pw.makeClient(user);

    return {user, client};
}

/**
 * Turns guest accounts on and gives back what undoes it, or undefined when the licence
 * has no guest accounts at all, which is the case's cue to skip.
 */
export async function enableGuestAccounts(adminClient: Client4): Promise<(() => Promise<void>) | undefined> {
    const license = await adminClient.getClientLicenseOld();
    if (license.GuestAccounts !== 'true') {
        return undefined;
    }

    const before = (await adminClient.getConfig()).GuestAccountsSettings.Enable;
    await adminClient.patchConfig({GuestAccountsSettings: {Enable: true}});

    return async () => {
        await adminClient.patchConfig({GuestAccountsSettings: {Enable: before}});
    };
}

export async function deleteFields(adminClient: Client4, fields: PropertyField[]): Promise<void> {
    for (const field of fields) {
        await ignoreMissing(() => adminClient.deletePropertyField(GROUP, OBJECT_TYPE, field.id));
    }
}

/**
 * Best-effort cleanup of fields an interrupted run left behind.
 *
 * Only the system scope is swept: a channel-scoped field belongs to a channel this run
 * created, so it dies with the fixture, while a system-scoped one applies everywhere
 * and would leak chips into an unrelated spec.
 */
export async function purgeFields(adminClient: Client4): Promise<void> {
    const fields = await adminClient.getPropertyFields(GROUP, OBJECT_TYPE, {targetType: 'system'});
    const stale = (fields ?? []).filter((field) => field.name.startsWith(FIELD_PREFIX) && field.delete_at === 0);

    await deleteFields(adminClient, stale);
}

/**
 * Collects the URLs of requests matching `fragment` into an array the caller asserts on.
 *
 * For asserting a request was *never* made, which `waitForResponse` cannot express — it
 * waits for something to happen, so the negative form is a timeout, and a timeout is a
 * guess about how long is long enough. Filtering here rather than at assert time keeps
 * the array small: a channel load makes hundreds of requests.
 *
 * Attach before the first navigation. The requests that matter are the ones the initial
 * channel load makes, and a listener added afterwards has already missed them.
 */
export function recordRequests(page: Page, fragment: string): string[] {
    const urls: string[] = [];

    page.on('request', (request: Request) => {
        if (request.url().includes(fragment)) {
            urls.push(request.url());
        }
    });

    return urls;
}

/**
 * Resolves with the request the composer sends to create a post. Arm it before the
 * click that sends, or the request is missed.
 *
 * Matches the path exactly, so the per-post values and reaction calls that share the
 * `/posts` prefix are not mistaken for it.
 */
export function waitForCreatePost(page: Page): Promise<Request> {
    return page.waitForRequest((request) => {
        return request.method() === 'POST' && new URL(request.url()).pathname.endsWith('/api/v4/posts');
    });
}

export type SentValue = {field_id: string; value: unknown};

/**
 * What a create-post request carried as `metadata.property_values`, or undefined when
 * the body has none.
 */
export function sentValues(request: Request): SentValue[] | undefined {
    return request.postDataJSON()?.metadata?.property_values;
}

/**
 * The active system-scoped fields on the server, for a case that needs "no other field"
 * to decide whether it can run. Call it after `purgeFields` and before the case creates
 * its own: anything left then is either not the suite's to touch, or one of the suite's
 * that the purge failed to delete, and either one would be offered alongside the case's.
 */
export async function activeSystemFields(adminClient: Client4): Promise<PropertyField[]> {
    const fields = await adminClient.getPropertyFields(GROUP, OBJECT_TYPE, {targetType: 'system'});
    return (fields ?? []).filter((field) => field.delete_at === 0);
}

/** Matches exactly `text`, for finding a chip by the option it shows. */
export function exactly(text: string): RegExp {
    return new RegExp(`^${text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`);
}

/**
 * The option chip on a post's attribute row that shows `name`. Option-bearing fields (`select`, `multiselect`,
 * `rank`) share one renderer, so their chips are told apart by the option they show.
 */
export function optionChip(
    attributes: generated.CenterPostListPostAttributes<generated.CenterPostListPostAttributesMount>,
    name: string,
): Locator {
    return attributes.value.selectText.locator.filter({hasText: exactly(name)});
}

/**
 * Opens the post's `…` menu with the pointer and picks `Attributes`, returning the modal.
 *
 * The message text is hovered rather than the post, so the pointer never rests on the chip row and the hover
 * card is not what opened the modal.
 */
export async function openModalFromPostMenu(
    app: App,
    post: generated.CenterPostListPost<generated.CenterPostListPostMount>,
) {
    await post.message.container.hover();
    await expect(post.menu.dotMenuButton).toBeVisible();
    const dotMenu = await post.menu.dotMenuButton.clickTo(app.postDotMenu);
    return dotMenu.postAttributesMenuItem.clickTo(app.postAttributesModal);
}

/** A composer: the centre channel's or the thread sidebar's. Both can be on screen at once. */
export type Composer = App['center']['postCreate'] | App['rhs']['postCreate'];

/**
 * Stages a field by opening the `+` in the action row and choosing it from the picker. A select field's value menu
 * opens by itself afterwards, and a text or user field's control takes focus.
 */
export async function stageField(composer: Composer, field: PropertyField) {
    const button = composer.postAttributesButton;

    await button.addButton.clickTo(button.addMenu);
    await button.addMenu.field(field).clickTo(composer.postAttributes.chip(field));
}

/**
 * Picks an option in the value menu a select or rank chip has open. The menu closes on the pick.
 */
export async function chooseOption(composer: Composer, field: PropertyField, name: string) {
    const menu = composer.postAttributes.chip(field).attribute.valueMenu;

    await menu.option(optionId(field, name)).click();
    await expect(menu.container).toBeHidden();
}

/**
 * Ticks an option in the value menu a multiselect chip has open. The menu stays open, so several can be ticked.
 */
export async function tickOption(composer: Composer, field: PropertyField, name: string) {
    const option = composer.postAttributes.chip(field).attribute.valueMenu.option(optionId(field, name));

    await option.click();
    await expect(option).toHaveAttribute('aria-checked', 'true');
}

/**
 * Types a value into a staged text chip and commits it with Enter, which rests the chip showing the value.
 */
export async function commitText(composer: Composer, field: PropertyField, value: string) {
    const chip = composer.postAttributes.chip(field);

    await chip.attribute.valueInputTextbox.fill(value);
    await chip.attribute.valueInputTextbox.press('Enter');
    await expect(chip.value.textText).toHaveText(value);
}

/**
 * Writes a message in the composer and sends it, resolving to the values the create request carried and the post the
 * server made.
 */
export async function sendMessage(page: Page, composer: Composer, message: string) {
    await composer.message.container.fill(message);

    const request = waitForCreatePost(page);
    const post = await settle(composer.sendButton, {wait: Api.CreatePost}).click();

    return {values: sentValues(await request), post};
}

/**
 * Removes a staged chip with its ×, and waits for it to leave the row.
 */
export async function removeChip(composer: Composer, field: PropertyField) {
    const chip = composer.postAttributes.chip(field);

    await chip.removeButton.click();
    await expect(chip.container).toHaveCount(0);
}

/**
 * Opens a post's thread from the centre column by its Reply button, and waits for the post to show in the sidebar. The
 * message text is hovered first, because the action row is hidden until the post is.
 */
export async function openThread(app: App, root: {id: string}) {
    const post = app.center.postList.post(root);

    await post.container.hover();
    await post.menu.replyButton.click();
    await expect(app.rhs.thread.post(root)).toBeVisible();
}
