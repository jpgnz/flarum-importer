<?php

namespace ErnestDefoe\Importer\Importers;

use Illuminate\Support\Carbon;
use Illuminate\Support\Str;

/**
 * Invision Community 4.x / 5.x (IP.Board) → Flarum.
 *   forums_forums → tags (titles live in core_sys_lang_words: forums_forum_{id})
 *   core_members  → users (bcrypt copies straight; legacy md5 → reset)
 *   forums_topics → discussions · forums_posts → posts
 * IPS post content is HTML (not BBCode); ipsHtml() cleans the IPS-specific markup.
 */
class InvisionImporter
{
    public static function fingerprint(array $cfg): string
    {
        $conn = Src::connect($cfg);
        foreach (['core_members', 'forums_forums', 'core_message_topics'] as $table) {
            if (! $conn->getSchemaBuilder()->hasTable($table)) {
                throw new \RuntimeException("Cannot fingerprint IPS source: missing {$table}.");
            }
        }
        $identity = [
            'members' => [(int) $conn->table('core_members')->count(), (int) $conn->table('core_members')->max('member_id')],
            'forums' => [(int) $conn->table('forums_forums')->count(), (int) $conn->table('forums_forums')->max('id')],
            'messages' => [(int) $conn->table('core_message_topics')->count(), (int) $conn->table('core_message_topics')->max('mt_id')],
        ];

        return hash('sha256', json_encode($identity));
    }

    public static function test(array $cfg): array
    {
        $conn = Src::connect($cfg);
        $sb = $conn->getSchemaBuilder();
        foreach (self::requiredTables() as $req) {
            if (! $sb->hasTable($req)) {
                throw new \RuntimeException("This doesn't look like an Invision Community database (missing {$req}).");
            }
        }

        $selectedTopics = self::selectedTopics($conn);
        $selectedPosts = self::selectedPosts($conn);
        $approved = (int) $conn->table('forums_topics')->where('approved', 1)->count();
        $topicCount = (int) $selectedTopics->count();
        $moved = (int) $conn->table('forums_topics')->where('approved', 1)
            ->where(fn ($query) => $query->where('state', 'link')->orWhereRaw("COALESCE(moved_to, '') <> ''"))->count();

        return ['ok' => true, 'counts' => [
            'groups' => (int) $conn->table('core_groups')->count(),
            'users' => (int) $conn->table('core_members')->where('member_id', '>', 0)->count(),
            'categories' => (int) $conn->table('forums_forums')->count(),
            'topics' => $topicCount,
            'posts' => (int) $selectedPosts->count(),
            'approved_topics' => $approved,
            'excluded_topics' => $approved - $topicCount,
            'moved_topics' => $moved,
            'invalid_first_post_topics' => max(0, $approved - $topicCount - $moved),
        ]];
    }

    /** @return Phase[] */
    public static function phases(array $cfg): array
    {
        if (! empty($cfg['ips_private_messages'])) {
            return self::privateMessagePhases($cfg);
        }

        $phases = [
            new Phase('preflight', 'Checking IPS source and target...',
                fn () => 1,
                function ($cursor, $limit, Ctx $ctx) {
                    self::preflight($ctx);

                    return ['cursor' => null, 'processed' => 1, 'done' => true, 'summary' => []];
                }
            ),

            new Phase('groups', 'Importing IPS groups...',
                fn () => (int) Src::connect($cfg)->table('core_groups')->count(),
                function ($cursor, $limit, Ctx $ctx) {
                    $rows = $ctx->src()->table('core_groups')->orderBy('g_id')->get();
                    $labels = self::groupWords($ctx->src(), $rows->pluck('g_id')->all());
                    $map = [];
                    foreach ($rows as $group) {
                        $sourceId = (int) $group->g_id;
                        if ($sourceId === 2) {
                            $map[$sourceId] = 2;
                        } elseif ($sourceId === 4) {
                            $map[$sourceId] = 1;
                        } else {
                            $label = trim($labels[$sourceId] ?? ('IPS Group ' . $sourceId));
                            $map[$sourceId] = Dst::group($label, $label, self::groupColor($group), $sourceId);
                        }
                    }
                    $ctx->mapPut('group', $map);

                    return ['cursor' => null, 'processed' => count($rows), 'done' => true, 'summary' => ['groups' => count($map)]];
                }
            ),

            new Phase('users', 'Importing IPS members...',
                fn () => (int) Src::connect($cfg)->table('core_members')->where('member_id', '>', 0)->count(),
                function ($cursor, $limit, Ctx $ctx) {
                    $rows = $ctx->src()->table('core_members')->where('member_id', '>', (int) $cursor)->orderBy('member_id')->limit($limit)->get();
                    $explicit = self::explicitUserMappings($ctx->cfg);
                    $map = [];
                    $n = $skip = 0;
                    foreach ($rows as $u) {
                        $sourceId = (int) $u->member_id;
                        $cursor = $sourceId;
                        $email = trim((string) ($u->email ?? ''));
                        $explicitTarget = $explicit[$sourceId] ?? null;
                        if ($explicitTarget === null && ($email === '' || ! filter_var($email, FILTER_VALIDATE_EMAIL))) {
                            $ctx->diagnostic('warning', 'ips_user_invalid_email', 'Skipped IPS member with an invalid email address.', 'user', $sourceId);
                            $skip++;
                            continue;
                        }

                        $base = self::normalizeUsername($u->name ?? null, $sourceId);
                        $username = $explicitTarget === null ? Dst::uniqueIpsUsername($base, $sourceId) : $base;
                        if ($explicitTarget === null && ($username !== trim((string) $u->name) || $username !== $base)) {
                            $ctx->diagnostic('info', 'ips_username_normalized', 'Normalized IPS username to ' . $username . '.', 'user', $sourceId);
                        }
                        $map[$sourceId] = Dst::ipsUser($username, $email, $u->members_pass_hash ?? null, Src::ts($u->joined ?? null), $explicitTarget);
                        $n++;
                    }
                    $ctx->mapPut('user', $map);

                    return ['cursor' => (int) $cursor, 'processed' => count($rows), 'done' => count($rows) < $limit, 'summary' => ['users' => $n, 'skipped' => $skip]];
                }
            ),

            new Phase('memberships', 'Importing IPS memberships...',
                fn () => (int) Src::connect($cfg)->table('core_members')->where('member_id', '>', 0)->count(),
                function ($cursor, $limit, Ctx $ctx) {
                    $rows = $ctx->src()->table('core_members')->where('member_id', '>', (int) $cursor)->orderBy('member_id')->limit($limit)->get(['member_id', 'member_group_id', 'mgroup_others']);
                    $userMap = $ctx->mapGet('user', $rows->pluck('member_id')->all());
                    $sourceGroupIds = [];
                    foreach ($rows as $member) {
                        $sourceGroupIds = array_merge($sourceGroupIds, self::memberGroupIds($member));
                    }
                    $groupMap = $ctx->mapGet('group', $sourceGroupIds);
                    $relations = 0;
                    foreach ($rows as $member) {
                        $cursor = (int) $member->member_id;
                        $userId = $userMap[(string) $member->member_id] ?? null;
                        if (! $userId) {
                            continue;
                        }
                        foreach (self::memberGroupIds($member) as $sourceGroupId) {
                            if (! isset($groupMap[(string) $sourceGroupId])) {
                                $ctx->diagnostic('warning', 'ips_membership_group_unmapped', 'Skipped membership in an unmapped IPS group.', 'user', $member->member_id, $userId, ['group_id' => $sourceGroupId]);
                                continue;
                            }
                            Dst::attachGroup($userId, $groupMap[(string) $sourceGroupId]);
                            $relations++;
                        }
                    }

                    return ['cursor' => (int) $cursor, 'processed' => count($rows), 'done' => count($rows) < $limit, 'summary' => ['memberships' => $relations]];
                }
            ),

            new Phase('tags', 'Importing IPS forums...',
                fn () => (int) Src::connect($cfg)->table('forums_forums')->count(),
                function ($cursor, $limit, Ctx $ctx) {
                    $forums = $ctx->src()->table('forums_forums')->orderBy('id')->get()->keyBy('id');
                    [$names, $descs] = self::forumWords($ctx->src(), $forums->keys()->all());
                    [$order, $roots, $positions] = self::orderedForums($forums);
                    $map = [];
                    foreach ($order as $sourceId) {
                        $forum = $forums[$sourceId];
                        if (self::isRedirectForum($forum)) {
                            $ctx->diagnostic('info', 'ips_forum_redirect_excluded', 'Excluded redirect-only IPS forum.', 'tag', $sourceId);
                            continue;
                        }
                        $rootId = $roots[$sourceId];
                        $parentId = $rootId === $sourceId ? null : ($map[$rootId] ?? null);
                        if ($rootId !== $sourceId && $parentId === null) {
                            throw new \RuntimeException("IPS forum {$sourceId} has no importable top-level root.");
                        }
                        $name = $names[$sourceId] ?? (($forum->name_seo ?? '') ? Str::headline((string) $forum->name_seo) : ('Forum ' . $sourceId));
                        $map[$sourceId] = Dst::ipsTag($name, Src::tagSlug($name, $sourceId), $descs[$sourceId] ?? null, $forum->feature_color ?? null, $positions[$sourceId], $parentId);
                    }
                    $ctx->mapPut('tag', $map);

                    return ['cursor' => null, 'processed' => count($forums), 'done' => true, 'summary' => ['categories' => count($map)]];
                }
            ),

            new Phase('permissions', 'Importing IPS forum permissions...',
                fn () => 1,
                function ($cursor, $limit, Ctx $ctx) {
                    self::importPermissions($ctx);

                    return ['cursor' => null, 'processed' => 1, 'done' => true, 'summary' => []];
                }
            ),

            new Phase('attachments-reserve', 'Reserving IPS attachments...',
                fn () => (int) self::selectedAttachments(Src::connect($cfg))->distinct()->count('a.attach_id'),
                function ($cursor, $limit, Ctx $ctx) {
                    $rows = self::selectedAttachments($ctx->src())->distinct()->where('a.attach_id', '>', (int) $cursor)
                        ->orderBy('a.attach_id')->limit($limit)->get(self::attachmentColumns())->unique('attach_id');
                    $reserved = $skipped = 0;
                    foreach ($rows as $attachment) {
                        $cursor = (int) $attachment->attach_id;
                        try {
                            IpsAssets::reserveAttachment($ctx, $attachment);
                            $reserved++;
                        } catch (IpsAssetUnavailable $error) {
                            $ctx->diagnostic('warning', 'ips_attachment_reserve_failed', $error->getMessage(), 'attachment', $attachment->attach_id);
                            $skipped++;
                        }
                    }

                    return ['cursor' => (int) $cursor, 'processed' => count($rows), 'done' => count($rows) < $limit, 'summary' => ['attachments_reserved' => $reserved, 'skipped' => $skipped]];
                }
            ),

            new Phase('attachments-finalize', 'Copying IPS attachments...',
                fn () => (int) self::selectedAttachments(Src::connect($cfg))->distinct()->count('a.attach_id'),
                function ($cursor, $limit, Ctx $ctx) {
                    $assets = Dst::db()->table('importer_assets')->where('run_id', $ctx->runId)->where('kind', 'attachment')
                        ->where('id', '>', (int) $cursor)->whereIn('state', [AssetJournal::RESERVED, AssetJournal::FINALIZED])
                        ->orderBy('id')->limit($limit)->get(['id', 'source_id', 'expected_size']);
                    $attachments = $ctx->src()->table('core_attachments as a')->whereIn('a.attach_id', $assets->pluck('source_id')->all())->get(self::attachmentColumns())->keyBy('attach_id');
                    $copied = $skipped = 0;
                    $bytes = 0;
                    foreach ($assets as $asset) {
                        $size = (int) ($asset->expected_size ?? 0);
                        if ($copied > 0 && $bytes + $size > 64 * 1024 * 1024) {
                            break;
                        }
                        $cursor = (int) $asset->id;
                        $attachment = $attachments[(int) $asset->source_id] ?? null;
                        if (! $attachment) {
                            $ctx->diagnostic('warning', 'ips_attachment_source_missing', 'Reserved IPS attachment no longer exists in the source.', 'attachment', $asset->source_id);
                            $skipped++;
                            continue;
                        }
                        IpsAssets::finalizeAttachment($ctx, $attachment);
                        $copied++;
                        $bytes += $size;
                    }

                    $processed = $copied + $skipped;

                    return ['cursor' => (int) $cursor, 'processed' => $processed, 'done' => count($assets) < $limit && $processed === count($assets), 'summary' => ['attachments_copied' => $copied, 'skipped' => $skipped]];
                }
            ),

            new Phase('topics', 'Importing selected IPS topics...',
                fn () => (int) Src::connect($cfg)->table('forums_topics')->where('approved', 1)->count(),
                function ($cursor, $limit, Ctx $ctx) {
                    $rows = $ctx->src()->table('forums_topics')->where('approved', 1)->where('tid', '>', (int) $cursor)->orderBy('tid')->limit($limit)->get();
                    $firstPosts = $ctx->src()->table('forums_posts')->whereIn('pid', $rows->pluck('topic_firstpost')->all())->get()->keyBy('pid');
                    $userMap = $ctx->mapGet('user', $rows->pluck('starter_id')->all());
                    $tagMap = $ctx->mapGet('tag', $rows->pluck('forum_id')->all());
                    $rootIds = self::forumRootIds($ctx->src(), $rows->pluck('forum_id')->all());
                    $rootMap = $ctx->mapGet('tag', array_values($rootIds));
                    $map = [];
                    $tagRelations = [];
                    $n = $skip = 0;
                    foreach ($rows as $t) {
                        $sourceId = (int) $t->tid;
                        $cursor = $sourceId;
                        if (($t->state ?? 'open') === 'link' || trim((string) ($t->moved_to ?? '')) !== '') {
                            $ctx->diagnostic('info', 'ips_topic_moved_excluded', 'Excluded moved or link IPS topic.', 'topic', $sourceId);
                            $skip++;
                            continue;
                        }
                        $first = $firstPosts[(int) $t->topic_firstpost] ?? null;
                        if (! $first || (int) $first->topic_id !== $sourceId || (int) $first->queued !== 0 || (int) $first->pdelete_time !== 0) {
                            $ctx->diagnostic('warning', 'ips_topic_invalid_first_post', 'Excluded IPS topic whose recorded first post is missing or not visible.', 'topic', $sourceId);
                            $skip++;
                            continue;
                        }
                        $forumTag = $tagMap[(string) $t->forum_id] ?? null;
                        $rootSourceId = $rootIds[(int) $t->forum_id] ?? null;
                        $rootTag = $rootSourceId === null ? null : ($rootMap[(string) $rootSourceId] ?? null);
                        if (! $forumTag || ! $rootTag) {
                            $ctx->diagnostic('warning', 'ips_topic_forum_unmapped', 'Excluded IPS topic in an unmapped forum.', 'topic', $sourceId);
                            $skip++;
                            continue;
                        }
                        $did = Dst::discussion($t->title ?: 'Untitled', (int) $t->starter_id === 0 ? null : ($userMap[(string) $t->starter_id] ?? null), Src::ts($t->start_date ?? null), (bool) ($t->pinned ?? false), ($t->state ?? 'open') === 'closed');
                        if ((int) $t->starter_id !== 0 && ! isset($userMap[(string) $t->starter_id])) {
                            $ctx->diagnostic('warning', 'ips_topic_author_unmapped', 'Imported IPS topic without its unmapped source author.', 'topic', $sourceId, $did);
                        }
                        $map[$sourceId] = $did;
                        $tagRelations[] = [$did, $rootTag];
                        if ($forumTag !== $rootTag) {
                            $tagRelations[] = [$did, $forumTag];
                        }
                        $n++;
                    }
                    Dst::attachNewTags($tagRelations);
                    $ctx->mapPut('topic', $map);

                    return ['cursor' => (int) $cursor, 'processed' => count($rows), 'done' => count($rows) < $limit, 'summary' => ['topics' => $n, 'skipped' => $skip]];
                }
            ),

            new Phase('posts', 'Importing selected IPS posts...',
                fn () => (int) self::selectedPosts(Src::connect($cfg))->count(),
                fn ($cursor, $limit, Ctx $ctx) => self::postsBatch($cursor, $limit, $ctx)
            ),

            new Phase('avatars', 'Importing IPS avatars...',
                fn () => (int) Src::connect($cfg)->table('core_members')->where('member_id', '>', 0)->where('pp_photo_type', 'custom')->count(),
                fn ($cursor, $limit, Ctx $ctx) => self::avatarsBatch($cursor, $limit, $ctx)
            ),

            ...self::optionalPhases($cfg),

            new Phase('counts-discussions', 'Updating IPS discussion counts...',
                fn () => 0,
                function ($cursor, $limit, Ctx $ctx) {
                    $rows = Dst::db()->table('importer_map')->where('run_id', $ctx->runId)->where('kind', 'topic')->where('id', '>', (int) $cursor)->orderBy('id')->limit($limit)->get(['id', 'target_id']);
                    foreach ($rows as $row) {
                        $cursor = (int) $row->id;
                        Dst::finalizeIpsDiscussion((int) $row->target_id);
                    }

                    return ['cursor' => (int) $cursor, 'processed' => 0, 'done' => count($rows) < $limit, 'summary' => []];
                }
            ),

            new Phase('counts-users', 'Updating IPS member counts...',
                fn () => 0,
                function ($cursor, $limit, Ctx $ctx) {
                    $rows = Dst::db()->table('importer_map')->where('run_id', $ctx->runId)->where('kind', 'user')->where('id', '>', (int) $cursor)->orderBy('id')->limit($limit)->get(['id', 'target_id']);
                    Dst::recountUsers($rows->pluck('target_id')->all());
                    if ($rows->isNotEmpty()) {
                        $cursor = (int) $rows->last()->id;
                    }

                    return ['cursor' => (int) $cursor, 'processed' => 0, 'done' => count($rows) < $limit, 'summary' => []];
                }
            ),

            new Phase('counts-tags', 'Updating IPS tag counts...',
                fn () => 0,
                function ($cursor, $limit, Ctx $ctx) {
                    $ids = Dst::db()->table('importer_map')->where('run_id', $ctx->runId)->where('kind', 'tag')->pluck('target_id')->all();
                    Dst::recountTags($ids);

                    return ['cursor' => null, 'processed' => 0, 'done' => true, 'summary' => []];
                }
            ),
        ];

        return $phases;
    }

    private static function optionalPhases(array $cfg): array
    {
        $phases = [];
        if (! empty($cfg['ips_reactions'])) {
            $phases[] = new Phase('reactions-definitions', 'Importing IPS reaction definitions...', fn () => 6,
                function ($cursor, $limit, Ctx $ctx) {
                    self::importReactionDefinitions($ctx);

                    return ['cursor' => null, 'processed' => 6, 'done' => true, 'summary' => []];
                });
            $phases[] = new Phase('reactions', 'Importing IPS reactions...',
                fn () => (int) Src::connect($cfg)->table('core_reputation_index')->whereIn('reaction', [1, 3, 4, 5, 8, 9])->where('rep_class', 'IPS\\forums\\Topic\\Post')->count(),
                fn ($cursor, $limit, Ctx $ctx) => self::reactionsBatch($cursor, $limit, $ctx));
        }
        if (! empty($cfg['ips_polls'])) {
            $phases[] = new Phase('polls', 'Importing recoverable IPS polls...',
                fn () => (int) Src::connect($cfg)->table('core_polls')->where('pid', '>', 1)->whereNotIn('choices', ['false', '0', ''])->count(),
                fn ($cursor, $limit, Ctx $ctx) => self::pollsBatch($cursor, $limit, $ctx));
        }
        if (! empty($cfg['ips_profiles'])) {
            $phases[] = new Phase('profile-fields', 'Importing IPS profile fields...', fn () => 5,
                function ($cursor, $limit, Ctx $ctx) {
                    self::importProfileFields($ctx);

                    return ['cursor' => null, 'processed' => 5, 'done' => true, 'summary' => []];
                });
            $phases[] = new Phase('profile-answers', 'Importing IPS profile answers...',
                fn () => (int) Src::connect($cfg)->table('core_pfields_content')->count(),
                fn ($cursor, $limit, Ctx $ctx) => self::profileAnswersBatch($cursor, $limit, $ctx));
        }
        if (! empty($cfg['ips_signatures'])) {
            $phases[] = new Phase('signatures', 'Importing IPS signatures...',
                fn () => (int) Src::connect($cfg)->table('core_members')->where('member_id', '>', 0)->whereRaw("COALESCE(TRIM(signature), '') <> ''")->count(),
                fn ($cursor, $limit, Ctx $ctx) => self::signaturesBatch($cursor, $limit, $ctx));
        }

        return $phases;
    }

    private static function privateMessagePhases(array $cfg): array
    {
        return [
            new Phase('pm-preflight', 'Checking IPS private messages...', fn () => 1,
                function ($cursor, $limit, Ctx $ctx) {
                    self::privateMessagePreflight($ctx);

                    return ['cursor' => null, 'processed' => 1, 'done' => true, 'summary' => []];
                }),
            new Phase('pm-topics', 'Importing IPS private conversations...',
                fn () => (int) Src::connect($cfg)->table('core_message_topics')->count(),
                fn ($cursor, $limit, Ctx $ctx) => self::privateTopicsBatch($cursor, $limit, $ctx)),
            new Phase('pm-attachments-reserve', 'Reserving IPS private-message attachments...',
                fn () => (int) Src::connect($cfg)->table('core_attachments_map')->where('location_key', 'core_Messaging')->distinct()->count('attachment_id'),
                fn ($cursor, $limit, Ctx $ctx) => self::privateAttachmentsReserveBatch($cursor, $limit, $ctx)),
            new Phase('pm-attachments-finalize', 'Copying IPS private-message attachments...',
                fn () => (int) Src::connect($cfg)->table('core_attachments_map')->where('location_key', 'core_Messaging')->distinct()->count('attachment_id'),
                fn ($cursor, $limit, Ctx $ctx) => self::privateAttachmentsFinalizeBatch($cursor, $limit, $ctx)),
            new Phase('pm-posts', 'Importing IPS private messages...',
                fn () => (int) Src::connect($cfg)->table('core_message_posts')->count(),
                fn ($cursor, $limit, Ctx $ctx) => self::privatePostsBatch($cursor, $limit, $ctx)),
            new Phase('pm-counts', 'Updating private conversation counts...', fn () => 0,
                function ($cursor, $limit, Ctx $ctx) {
                    $rows = Dst::db()->table('importer_map')->where('run_id', $ctx->runId)->where('kind', 'pm-topic')
                        ->where('id', '>', (int) $cursor)->orderBy('id')->limit($limit)->get(['id', 'target_id']);
                    foreach ($rows as $row) {
                        $cursor = (int) $row->id;
                        Dst::finalizeIpsDiscussion((int) $row->target_id);
                    }

                    return ['cursor' => (int) $cursor, 'processed' => 0, 'done' => count($rows) < $limit, 'summary' => []];
                }),
            new Phase('pm-state', 'Importing private-message read state...',
                fn () => (int) Src::connect($cfg)->table('core_message_topic_user_map')->count(),
                fn ($cursor, $limit, Ctx $ctx) => self::privateStateBatch($cursor, $limit, $ctx)),
        ];
    }

    private static function privateMessagePreflight(Ctx $ctx): void
    {
        if (! $ctx->baseRunId) {
            throw new \RuntimeException('IPS private-message import requires a completed public base run.');
        }
        $schema = $ctx->src()->getSchemaBuilder();
        foreach (['core_message_topics', 'core_message_posts', 'core_message_topic_user_map', 'core_attachments', 'core_attachments_map'] as $table) {
            if (! $schema->hasTable($table)) {
                throw new \RuntimeException("IPS private-message preflight failed: missing source table {$table}.");
            }
        }
        $sourceColumns = [
            'core_message_topics' => ['mt_id', 'mt_title', 'mt_starter_id', 'mt_start_time', 'mt_last_post_time', 'mt_first_msg_id', 'mt_is_draft', 'mt_is_deleted', 'mt_is_system'],
            'core_message_posts' => ['msg_id', 'msg_topic_id', 'msg_date', 'msg_post', 'msg_author_id', 'msg_ip_address', 'msg_is_first_post'],
            'core_message_topic_user_map' => [
                'map_id', 'map_user_id', 'map_topic_id', 'map_user_active', 'map_left_time',
                'map_read_time', 'map_has_unread', 'map_ignore_notification', 'map_last_topic_reply',
            ],
        ];
        foreach ($sourceColumns as $table => $columns) {
            foreach ($columns as $column) {
                if (! $schema->hasColumn($table, $column)) {
                    throw new \RuntimeException("IPS private-message preflight failed: missing source column {$table}.{$column}.");
                }
            }
        }
        foreach (['discussions', 'posts', 'recipients', 'discussion_user', 'importer_pm_mutes', 'fof_upload_files', 'fof_upload_file_posts'] as $table) {
            if (! Dst::hasTable($table)) {
                throw new \RuntimeException("IPS private-message preflight failed: missing target table {$table}.");
            }
        }
        foreach ([
            'discussions' => ['id', 'title', 'user_id', 'is_private', 'is_approved'],
            'posts' => ['id', 'discussion_id', 'number', 'user_id', 'content', 'ip_address', 'is_private', 'is_approved'],
            'recipients' => ['discussion_id', 'user_id', 'group_id', 'removed_at'],
            'discussion_user' => ['discussion_id', 'user_id', 'last_read_at', 'last_read_post_number', 'subscription'],
        ] as $table => $columns) {
            foreach ($columns as $column) {
                if (! Dst::hasColumn($table, $column)) {
                    throw new \RuntimeException("IPS private-message preflight failed: missing target column {$table}.{$column}.");
                }
            }
        }
        $base = Dst::db()->table('importer_runs')->where('id', $ctx->baseRunId)->first(['source', 'status']);
        if (! $base || $base->source !== 'invision' || $base->status !== 'done') {
            throw new \RuntimeException('IPS private-message base run must be a completed Invision import.');
        }
        $enabled = json_decode((string) Dst::db()->table('settings')->where('key', 'extensions_enabled')->value('value'), true);
        foreach (['fof-byobu', 'fof-upload'] as $extension) {
            if (! is_array($enabled) || ! in_array($extension, $enabled, true)) {
                throw new \RuntimeException("IPS private-message preflight failed: {$extension} is not enabled.");
            }
        }
        IpsAssets::validateConfig($ctx->cfg);

        $attachmentCursor = 0;
        do {
            $attachments = $ctx->src()->table('core_attachments as a')
                ->join('core_attachments_map as am', 'am.attachment_id', '=', 'a.attach_id')
                ->where('am.location_key', 'core_Messaging')->whereNotNull('am.id1')->whereNotNull('am.id2')
                ->where('a.attach_id', '>', $attachmentCursor)->distinct()->orderBy('a.attach_id')->limit(500)->get(self::attachmentColumns());
            foreach ($attachments as $attachment) {
                $attachmentCursor = (int) $attachment->attach_id;
                try {
                    IpsAssets::inspectAttachment($ctx->cfg, $attachment);
                } catch (IpsAssetUnavailable $error) {
                    $ctx->diagnostic('warning', 'ips_pm_attachment_unavailable', $error->getMessage(), 'attachment', $attachment->attach_id);
                }
            }
        } while (count($attachments) === 500);

        $noActive = (int) $ctx->src()->table('core_message_topics as t')->whereNotExists(function ($query) {
            $query->selectRaw('1')->from('core_message_topic_user_map as m')->whereColumn('m.map_topic_id', 't.mt_id')->where('m.map_user_active', 1);
        })->count();
        $selectedTopics = self::selectedPrivateTopics($ctx->src());
        $selectedTopicCount = (int) (clone $selectedTopics)->count();
        $selectedPostCount = (int) $ctx->src()->table('core_message_posts as p')
            ->joinSub($selectedTopics->select('t.mt_id'), 'selected_pm_topics', 'selected_pm_topics.mt_id', '=', 'p.msg_topic_id')->count();
        $ctx->diagnostic('info', 'ips_pm_preflight', 'Private-message preflight completed.', null, null, null, [
            'topics' => (int) $ctx->src()->table('core_message_topics')->count(),
            'posts' => (int) $ctx->src()->table('core_message_posts')->count(),
            'selected_topics_before_base_mapping' => $selectedTopicCount,
            'selected_posts_before_base_mapping' => $selectedPostCount,
            'no_active_recipient_topics' => $noActive,
        ]);
    }

    private static function selectedPrivateTopics($conn)
    {
        return $conn->table('core_message_topics as t')
            ->join('core_message_posts as fp', function ($join) {
                $join->on('fp.msg_id', '=', 't.mt_first_msg_id')->on('fp.msg_topic_id', '=', 't.mt_id')->where('fp.msg_is_first_post', 1);
            })
            ->where('t.mt_is_draft', 0)->where('t.mt_is_deleted', 0)->where('t.mt_is_system', 0)
            ->whereExists(function ($query) {
                $query->selectRaw('1')->from('core_message_topic_user_map as mp')
                    ->join('core_members as member', 'member.member_id', '=', 'mp.map_user_id')
                    ->whereColumn('mp.map_topic_id', 't.mt_id')->where('mp.map_user_active', 1);
            });
    }

    private static function privateTopicsBatch($cursor, int $limit, Ctx $ctx): array
    {
        $rows = $ctx->src()->table('core_message_topics')->where('mt_id', '>', (int) $cursor)
            ->where('mt_is_draft', 0)->where('mt_is_deleted', 0)->where('mt_is_system', 0)
            ->orderBy('mt_id')->limit($limit)->get();
        $firstPosts = $ctx->src()->table('core_message_posts')->whereIn('msg_id', $rows->pluck('mt_first_msg_id')->all())->get()->keyBy('msg_id');
        $participantRows = $ctx->src()->table('core_message_topic_user_map')->whereIn('map_topic_id', $rows->pluck('mt_id')->all())->orderBy('map_id')->get();
        $participantsByTopic = [];
        foreach ($participantRows as $participant) {
            $participantsByTopic[(int) $participant->map_topic_id][] = $participant;
        }
        $userMap = $ctx->mapGet('user', array_merge($rows->pluck('mt_starter_id')->all(), $participantRows->pluck('map_user_id')->all()));
        $map = [];
        $imported = $skipped = $recipients = 0;
        foreach ($rows as $topic) {
            $cursor = (int) $topic->mt_id;
            $first = $firstPosts[(int) $topic->mt_first_msg_id] ?? null;
            if (! $first || (int) $first->msg_topic_id !== (int) $topic->mt_id || (int) $first->msg_is_first_post !== 1) {
                $ctx->diagnostic('warning', 'ips_pm_invalid_first_message', 'Skipped private conversation with an invalid recorded first message.', 'pm-topic', $topic->mt_id);
                $skipped++;
                continue;
            }
            $topicParticipants = $participantsByTopic[(int) $topic->mt_id] ?? [];
            $activeMapped = array_filter($topicParticipants, fn ($p) => (int) $p->map_user_active === 1 && isset($userMap[(string) $p->map_user_id]));
            if (! $activeMapped) {
                $ctx->diagnostic('warning', 'ips_pm_no_active_recipient', 'Skipped private conversation with no mapped active recipient.', 'pm-topic', $topic->mt_id);
                $skipped++;
                continue;
            }
            $starterId = $userMap[(string) $topic->mt_starter_id] ?? null;
            $discussionId = Dst::privateDiscussion((string) $topic->mt_title, $starterId, Src::ts($first->msg_date ?? $topic->mt_start_time));
            $map[(int) $topic->mt_id] = $discussionId;
            if (mb_strlen((string) $topic->mt_title) > 200) {
                $ctx->diagnostic('info', 'ips_pm_title_truncated', 'Truncated private conversation title to the target limit.', 'pm-topic', $topic->mt_id, $discussionId);
            }
            foreach ($topicParticipants as $participant) {
                $userId = $userMap[(string) $participant->map_user_id] ?? null;
                if (! $userId) {
                    $ctx->diagnostic('warning', 'ips_pm_recipient_unmapped', 'Skipped private conversation participant without a public user mapping.', 'pm-recipient', $participant->map_id, $discussionId);
                    continue;
                }
                $removedAt = null;
                if ((int) $participant->map_user_active !== 1) {
                    $removedAt = Src::ts((int) $participant->map_left_time > 0 ? $participant->map_left_time : $topic->mt_last_post_time);
                    if ((int) $participant->map_left_time <= 0) {
                        $ctx->diagnostic('info', 'ips_pm_recipient_leave_time_inferred', 'Used the conversation last-post time for an inactive participant without a leave timestamp.', 'pm-recipient', $participant->map_id, $discussionId);
                    }
                }
                if (! Dst::db()->table('recipients')->where('discussion_id', $discussionId)->where('user_id', $userId)->exists()) {
                    $createdAt = Src::ts($topic->mt_start_time ?: $topic->mt_date);
                    Dst::db()->table('recipients')->insert([
                        'discussion_id' => $discussionId,
                        'user_id' => $userId,
                        'group_id' => null,
                        'created_at' => $createdAt,
                        'updated_at' => $createdAt,
                        'removed_at' => $removedAt,
                    ]);
                    $recipients++;
                }
                if ((int) ($participant->map_ignore_notification ?? 0) === 1) {
                    Dst::db()->table('importer_pm_mutes')->insertOrIgnore([
                        'discussion_id' => $discussionId,
                        'user_id' => $userId,
                        'created_at' => Carbon::now(),
                    ]);
                }
            }
            $imported++;
        }
        $ctx->mapPut('pm-topic', $map);

        return ['cursor' => (int) $cursor, 'processed' => count($rows), 'done' => count($rows) < $limit, 'summary' => ['pm_topics' => $imported, 'pm_recipients' => $recipients, 'skipped' => $skipped]];
    }

    private static function privateAttachmentsReserveBatch($cursor, int $limit, Ctx $ctx): array
    {
        $rows = $ctx->src()->table('core_attachments as a')
            ->join('core_attachments_map as am', 'am.attachment_id', '=', 'a.attach_id')
            ->where('am.location_key', 'core_Messaging')->where('a.attach_id', '>', (int) $cursor)
            ->whereNotNull('am.id1')->whereNotNull('am.id2')
            ->distinct()->orderBy('a.attach_id')->limit($limit)->get(self::attachmentColumns());
        $topicIds = $ctx->src()->table('core_attachments_map')->where('location_key', 'core_Messaging')
            ->whereIn('attachment_id', $rows->pluck('attach_id')->all())->pluck('id1')->all();
        $topicMap = $ctx->mapGet('pm-topic', $topicIds);
        $baseFiles = $ctx->mapGet('attachment', $rows->pluck('attach_id')->all());
        $reserved = $reused = $skipped = 0;
        foreach ($rows as $attachment) {
            $cursor = (int) $attachment->attach_id;
            $mappedTopics = $ctx->src()->table('core_attachments_map')->where('location_key', 'core_Messaging')
                ->where('attachment_id', $attachment->attach_id)->whereNotNull('id1')->pluck('id1')->all();
            $selected = array_filter($mappedTopics, fn ($topicId) => isset($topicMap[(string) $topicId]));
            if (! $selected) {
                $skipped++;
                continue;
            }
            if (isset($baseFiles[(string) $attachment->attach_id])) {
                $reused++;
                continue;
            }
            try {
                IpsAssets::reserveAttachment($ctx, $attachment);
                $reserved++;
            } catch (IpsAssetUnavailable $error) {
                $ctx->diagnostic('warning', 'ips_pm_attachment_unavailable', $error->getMessage(), 'attachment', $attachment->attach_id);
                $skipped++;
            }
        }

        return ['cursor' => (int) $cursor, 'processed' => count($rows), 'done' => count($rows) < $limit, 'summary' => ['pm_attachments_reserved' => $reserved, 'pm_attachments_reused' => $reused, 'skipped' => $skipped]];
    }

    private static function privateAttachmentsFinalizeBatch($cursor, int $limit, Ctx $ctx): array
    {
        $assets = Dst::db()->table('importer_assets')->where('run_id', $ctx->runId)->where('kind', 'attachment')
            ->where('id', '>', (int) $cursor)->whereIn('state', [AssetJournal::RESERVED, AssetJournal::FINALIZED])
            ->orderBy('id')->limit($limit)->get(['id', 'source_id', 'expected_size']);
        $attachments = $ctx->src()->table('core_attachments as a')->whereIn('a.attach_id', $assets->pluck('source_id')->all())
            ->get(self::attachmentColumns())->keyBy('attach_id');
        $copied = $bytes = $processed = 0;
        foreach ($assets as $asset) {
            $size = (int) ($asset->expected_size ?? 0);
            if ($processed > 0 && $bytes + $size > 64 * 1024 * 1024) {
                break;
            }
            $cursor = (int) $asset->id;
            $attachment = $attachments[(int) $asset->source_id] ?? null;
            if (! $attachment) {
                throw new \RuntimeException("Reserved PM attachment {$asset->source_id} no longer exists in the source.");
            }
            IpsAssets::finalizeAttachment($ctx, $attachment);
            $copied++;
            $processed++;
            $bytes += $size;
        }

        return ['cursor' => (int) $cursor, 'processed' => $processed, 'done' => count($assets) < $limit && $processed === count($assets), 'summary' => ['pm_attachments_copied' => $copied]];
    }

    private static function privatePostsBatch($cursor, int $limit, Ctx $ctx): array
    {
        $cur = is_array($cursor) ? $cursor : ['tid' => 0, 'rank' => 0, 'at' => 0, 'pid' => 0, 'num' => 0];
        $topicIds = $ctx->src()->table('core_message_topics as t')
            ->join('core_message_posts as fp', function ($join) {
                $join->on('fp.msg_id', '=', 't.mt_first_msg_id')->on('fp.msg_topic_id', '=', 't.mt_id')->where('fp.msg_is_first_post', 1);
            })
            ->where('t.mt_is_draft', 0)->where('t.mt_is_deleted', 0)->where('t.mt_is_system', 0)
            ->where('t.mt_id', '>=', (int) $cur['tid'])
            ->orderBy('t.mt_id')->limit($limit + 1)->pluck('t.mt_id')->all();
        $rows = $ctx->src()->table('core_message_posts as p')->join('core_message_topics as t', 't.mt_id', '=', 'p.msg_topic_id')
            ->whereIn('p.msg_topic_id', $topicIds)
            ->where(function ($query) use ($cur) {
                $query->where('p.msg_topic_id', '>', (int) $cur['tid'])
                    ->orWhere(function ($query) use ($cur) {
                        $query->where('p.msg_topic_id', (int) $cur['tid'])->where(function ($query) use ($cur) {
                            $query->whereRaw('(CASE WHEN p.msg_id = t.mt_first_msg_id THEN 0 ELSE 1 END) > ?', [(int) $cur['rank']])
                                ->orWhere(function ($query) use ($cur) {
                                    $query->whereRaw('(CASE WHEN p.msg_id = t.mt_first_msg_id THEN 0 ELSE 1 END) = ?', [(int) $cur['rank']])
                                        ->where(function ($query) use ($cur) {
                                            $query->whereRaw('COALESCE(p.msg_date, 0) > ?', [(int) $cur['at']])
                                                ->orWhere(function ($query) use ($cur) {
                                                    $query->whereRaw('COALESCE(p.msg_date, 0) = ?', [(int) $cur['at']])->where('p.msg_id', '>', (int) $cur['pid']);
                                                });
                                        });
                                });
                        });
                    });
            })
            ->orderBy('p.msg_topic_id')->orderByRaw('CASE WHEN p.msg_id = t.mt_first_msg_id THEN 0 ELSE 1 END')
            ->orderByRaw('COALESCE(p.msg_date, 0)')->orderBy('p.msg_id')->limit($limit)
            ->get(['p.msg_id', 'p.msg_topic_id', 'p.msg_date', 'p.msg_post', 'p.msg_author_id', 'p.msg_ip_address', 't.mt_first_msg_id']);
        $topicMap = $ctx->mapGet('pm-topic', $rows->pluck('msg_topic_id')->all());
        $userMap = $ctx->mapGet('user', $rows->pluck('msg_author_id')->all());
        $attachmentRows = $ctx->src()->table('core_attachments_map as am')->join('core_attachments as a', 'a.attach_id', '=', 'am.attachment_id')
            ->where('am.location_key', 'core_Messaging')->whereIn('am.id2', $rows->pluck('msg_id')->all())
            ->orderBy('a.attach_id')->get(array_merge(self::attachmentColumns(), ['am.id2 as mapped_post_id']));
        $attachmentsByPost = [];
        foreach ($attachmentRows as $attachment) {
            $attachmentsByPost[(int) $attachment->mapped_post_id][(int) $attachment->attach_id] ??= $attachment;
        }
        $postMap = [];
        $imported = $skipped = 0;
        foreach ($rows as $message) {
            $topicId = (int) $message->msg_topic_id;
            if ($topicId !== (int) $cur['tid']) {
                $cur['num'] = 0;
            }
            $cur['tid'] = $topicId;
            $cur['rank'] = (int) $message->msg_id === (int) $message->mt_first_msg_id ? 0 : 1;
            $cur['at'] = (int) ($message->msg_date ?? 0);
            $cur['pid'] = (int) $message->msg_id;
            $discussionId = $topicMap[(string) $topicId] ?? null;
            if (! $discussionId) {
                $skipped++;
                continue;
            }

            $postAttachments = $attachmentsByPost[(int) $message->msg_id] ?? [];
            [$rawHtml, $inlineAttachmentIds] = IpsAssets::rewriteHtml((string) ($message->msg_post ?? ''), $postAttachments);
            $html = self::ipsHtml($rawHtml);
            $previews = [];
            $files = [];
            foreach ($postAttachments as $attachmentId => $attachment) {
                $fileMap = $ctx->mapGet('attachment', [$attachmentId]);
                $fileId = $fileMap[(string) $attachmentId] ?? null;
                if ($fileId) {
                    [$file, $preview] = IpsAssets::existingAttachment($ctx, $attachment, $fileId);
                } else {
                    $asset = AssetJournal::get($ctx, 'attachment', $attachmentId);
                    if (! $asset || ! in_array($asset->state, [AssetJournal::FINALIZED, AssetJournal::LINKED], true)) {
                        $ctx->diagnostic('warning', 'ips_pm_attachment_not_finalized', 'Skipped PM attachment that was not finalized.', 'attachment', $attachmentId, null, ['message_id' => (int) $message->msg_id]);
                        continue;
                    }
                    [$file, $preview] = IpsAssets::linkAttachment($ctx, $attachment, $asset, true);
                }
                $files[$attachmentId] = $file;
                $previews[$attachmentId] = $preview;
            }
            $markdown = IpsAssets::substitute(Dst::markdown($html), $previews, $inlineAttachmentIds);
            if (str_contains($markdown, 'IPSATTACHMENTTOKEN') || str_contains($markdown, 'fileStore.core_Attachment')) {
                $ctx->diagnostic('warning', 'ips_pm_attachment_markup_unresolved', 'Removed unresolved IPS attachment markup from a private message.', 'pm-post', $message->msg_id);
                $markdown = preg_replace('/IPSATTACHMENTTOKEN\d+ENDTOKEN/', '[attachment unavailable]', $markdown) ?? $markdown;
                $markdown = str_replace('fileStore.core_Attachment', '', $markdown);
            }
            $authorId = (int) $message->msg_author_id;
            $targetUserId = $authorId > 0 ? ($userMap[(string) $authorId] ?? null) : null;
            if ($authorId > 0 && ! $targetUserId) {
                $ctx->diagnostic('warning', 'ips_pm_author_unmapped', 'Imported private message without its missing source author.', 'pm-post', $message->msg_id);
            }
            $number = ++$cur['num'];
            $ip = filter_var((string) $message->msg_ip_address, FILTER_VALIDATE_IP) ? (string) $message->msg_ip_address : null;
            $targetPostId = Dst::privateParsedPost($discussionId, $number, $targetUserId, Dst::parseMarkdown($markdown), Src::ts($message->msg_date), $ip);
            $postMap[(int) $message->msg_id] = $targetPostId;
            foreach ($files as $file) {
                IpsAssets::attachToPost((int) $file->id, $targetPostId);
            }
            $imported++;
        }
        $ctx->mapPut('pm-post', $postMap);

        return ['cursor' => $cur, 'processed' => count($rows), 'done' => count($rows) < $limit, 'summary' => ['pm_posts' => $imported, 'skipped' => $skipped]];
    }

    private static function privateStateBatch($cursor, int $limit, Ctx $ctx): array
    {
        $rows = $ctx->src()->table('core_message_topic_user_map')->where('map_id', '>', (int) $cursor)
            ->orderBy('map_id')->limit($limit)->get([
                'map_id', 'map_user_id', 'map_topic_id', 'map_read_time', 'map_has_unread',
            ]);
        $topicMap = $ctx->mapGet('pm-topic', $rows->pluck('map_topic_id')->all());
        $userMap = $ctx->mapGet('user', $rows->pluck('map_user_id')->all());
        $discussionIds = array_values(array_unique(array_filter(array_map(
            fn ($topicId) => $topicMap[(string) $topicId] ?? null,
            $rows->pluck('map_topic_id')->all()
        ))));
        $postsByDiscussion = [];
        if ($discussionIds) {
            foreach (Dst::db()->table('posts')->whereIn('discussion_id', $discussionIds)->where('type', 'comment')
                ->orderBy('discussion_id')->orderBy('number')->get(['discussion_id', 'number', 'created_at']) as $post) {
                $postsByDiscussion[(int) $post->discussion_id][] = $post;
            }
        }

        $imported = $skipped = 0;
        foreach ($rows as $state) {
            $cursor = (int) $state->map_id;
            $discussionId = $topicMap[(string) $state->map_topic_id] ?? null;
            $userId = $userMap[(string) $state->map_user_id] ?? null;
            if (! $discussionId || ! $userId) {
                $skipped++;
                continue;
            }
            $posts = $postsByDiscussion[(int) $discussionId] ?? [];
            if (! $posts) {
                $ctx->diagnostic('warning', 'ips_pm_state_no_posts', 'Skipped private-message state because the imported conversation has no posts.', 'pm-recipient', $state->map_id, $discussionId);
                $skipped++;
                continue;
            }
            $readTime = (int) $state->map_read_time;
            $lastReadNumber = IpsPrivateMessageState::lastReadPostNumber($posts, (int) $state->map_has_unread === 1, $readTime);

            Dst::db()->table('discussion_user')->updateOrInsert(
                ['discussion_id' => $discussionId, 'user_id' => $userId],
                [
                    'last_read_at' => $readTime > 0 ? Carbon::createFromTimestamp($readTime) : null,
                    'last_read_post_number' => $lastReadNumber,
                    'subscription' => null,
                ]
            );
            $imported++;
        }

        return ['cursor' => (int) $cursor, 'processed' => count($rows), 'done' => count($rows) < $limit, 'summary' => ['pm_states' => $imported, 'skipped' => $skipped]];
    }

    private static function requiredTables(): array
    {
        return ['core_groups', 'core_members', 'core_moderators', 'core_permission_index', 'core_sys_lang', 'core_sys_lang_words', 'core_attachments', 'core_attachments_map', 'forums_forums', 'forums_topics', 'forums_posts'];
    }

    private static function selectedTopics($conn)
    {
        // MariaDB may otherwise start at forums_forums and rescan every approved topic per batch.
        $topics = $conn->getDriverName() === 'mysql'
            ? $conn->raw($conn->getTablePrefix() . 'forums_topics as t FORCE INDEX (PRIMARY)')
            : 'forums_topics as t';

        return $conn->table($topics)
            ->join('forums_posts as fp', function ($join) {
                $join->on('fp.pid', '=', 't.topic_firstpost')->on('fp.topic_id', '=', 't.tid');
            })
            ->join('forums_forums as f', 'f.id', '=', 't.forum_id')
            ->where('t.approved', 1)->where('fp.queued', 0)->where('fp.pdelete_time', 0)
            ->whereRaw("COALESCE(t.state, '') <> 'link'")->whereRaw("COALESCE(t.moved_to, '') = ''")
            ->whereRaw("NOT (f.redirect_on = 1 AND COALESCE(f.redirect_url, '') <> '')");
    }

    private static function selectedPosts($conn)
    {
        return $conn->table('forums_posts as p')
            ->join('forums_topics as t', 't.tid', '=', 'p.topic_id')
            ->join('forums_posts as fp', function ($join) {
                $join->on('fp.pid', '=', 't.topic_firstpost')->on('fp.topic_id', '=', 't.tid');
            })
            ->join('forums_forums as f', 'f.id', '=', 't.forum_id')
            ->where('t.approved', 1)->where('fp.queued', 0)->where('fp.pdelete_time', 0)
            ->where('p.queued', 0)->where('p.pdelete_time', 0)
            ->whereRaw("COALESCE(t.state, '') <> 'link'")->whereRaw("COALESCE(t.moved_to, '') = ''")
            ->whereRaw("NOT (f.redirect_on = 1 AND COALESCE(f.redirect_url, '') <> '')");
    }

    private static function selectedAttachments($conn)
    {
        return $conn->table('core_attachments as a')
            ->join('core_attachments_map as am', 'am.attachment_id', '=', 'a.attach_id')
            ->join('forums_posts as p', 'p.pid', '=', 'am.id2')
            ->join('forums_topics as t', 't.tid', '=', 'p.topic_id')
            ->join('forums_posts as fp', function ($join) {
                $join->on('fp.pid', '=', 't.topic_firstpost')->on('fp.topic_id', '=', 't.tid');
            })
            ->join('forums_forums as f', 'f.id', '=', 't.forum_id')
            ->where('am.location_key', 'forums_Forums')
            ->where('t.approved', 1)->where('fp.queued', 0)->where('fp.pdelete_time', 0)
            ->where('p.queued', 0)->where('p.pdelete_time', 0)
            ->whereRaw("COALESCE(t.state, '') <> 'link'")->whereRaw("COALESCE(t.moved_to, '') = ''")
            ->whereRaw("NOT (f.redirect_on = 1 AND COALESCE(f.redirect_url, '') <> '')");
    }

    private static function attachmentColumns(): array
    {
        return [
            'a.attach_id', 'a.attach_file', 'a.attach_location', 'a.attach_thumb_location', 'a.attach_is_image',
            'a.attach_date', 'a.attach_member_id', 'a.attach_filesize', 'a.attach_img_width', 'a.attach_img_height', 'a.attach_security_key',
        ];
    }

    private static function preflight(Ctx $ctx): void
    {
        $conn = $ctx->src();
        $schema = $conn->getSchemaBuilder();
        foreach (self::requiredTables() as $table) {
            if (! $schema->hasTable($table)) {
                throw new \RuntimeException("IPS preflight failed: missing source table {$table}.");
            }
        }
        $sourceColumns = [
            'core_groups' => ['g_id', 'g_view_board', 'g_attach_max'],
            'core_members' => ['member_id', 'name', 'email', 'members_pass_hash', 'joined', 'member_group_id', 'mgroup_others'],
            'core_moderators' => ['id', 'type', 'perms'],
            'core_attachments' => ['attach_id', 'attach_file', 'attach_location', 'attach_thumb_location', 'attach_is_image', 'attach_date', 'attach_member_id', 'attach_filesize', 'attach_security_key'],
            'core_attachments_map' => ['attachment_id', 'location_key', 'id1', 'id2', 'temp'],
            'core_permission_index' => ['app', 'perm_type', 'perm_type_id', 'perm_view', 'perm_2', 'perm_3', 'perm_4', 'perm_5'],
            'core_sys_lang' => ['lang_id', 'lang_short', 'lang_title'],
            'core_sys_lang_words' => ['lang_id', 'word_app', 'word_key', 'word_default', 'word_custom'],
            'forums_forums' => ['id', 'parent_id', 'position', 'redirect_on', 'redirect_url', 'sub_can_post', 'permission_showtopic', 'min_posts_post', 'min_posts_view', 'can_view_others', 'password'],
            'forums_topics' => ['tid', 'title', 'state', 'starter_id', 'starter_name', 'start_date', 'forum_id', 'approved', 'pinned', 'moved_to', 'topic_firstpost'],
            'forums_posts' => ['pid', 'author_id', 'author_name', 'post_date', 'post', 'queued', 'topic_id', 'pdelete_time'],
        ];
        foreach ($sourceColumns as $table => $columns) {
            foreach ($columns as $column) {
                if (! $schema->hasColumn($table, $column)) {
                    throw new \RuntimeException("IPS preflight failed: missing source column {$table}.{$column}.");
                }
            }
        }
        foreach (['groups', 'group_user', 'users', 'tags', 'group_permission', 'discussions', 'discussion_tag', 'posts', 'settings', 'fof_upload_files', 'fof_upload_file_posts'] as $table) {
            if (! Dst::hasTable($table)) {
                throw new \RuntimeException("IPS preflight failed: missing target table {$table}.");
            }
        }
        $targetColumns = [
            'groups' => ['id', 'name_singular', 'name_plural', 'color', 'icon', 'is_hidden', 'position'],
            'group_user' => ['user_id', 'group_id'],
            'users' => ['id', 'username', 'email', 'password', 'joined_at', 'discussion_count', 'comment_count'],
            'tags' => ['id', 'name', 'slug', 'description', 'color', 'is_primary', 'position', 'parent_id', 'is_restricted', 'is_hidden', 'discussion_count'],
            'group_permission' => ['group_id', 'permission'],
            'discussions' => ['id', 'title', 'slug', 'created_at', 'user_id', 'first_post_id', 'last_post_id', 'last_post_number', 'last_posted_at', 'last_posted_user_id', 'comment_count', 'participant_count', 'is_private'],
            'discussion_tag' => ['discussion_id', 'tag_id'],
            'posts' => ['id', 'discussion_id', 'number', 'created_at', 'user_id', 'type', 'content', 'is_private'],
        ];
        foreach ($targetColumns as $table => $columns) {
            foreach ($columns as $column) {
                if (! Dst::hasColumn($table, $column)) {
                    throw new \RuntimeException("IPS preflight failed: missing target column {$table}.{$column}.");
                }
            }
        }

        $enabled = json_decode((string) Dst::db()->table('settings')->where('key', 'extensions_enabled')->value('value'), true);
        if (! is_array($enabled)) {
            throw new \RuntimeException('IPS preflight failed: enabled extension inventory is unavailable.');
        }
        foreach (['flarum-tags', 'fof-upload'] as $extension) {
            if (! in_array($extension, $enabled, true)) {
                throw new \RuntimeException("IPS preflight failed: required extension {$extension} is not enabled.");
            }
        }
        $optional = [
            'ips_reactions' => ['fof-reactions', ['reactions', 'post_reactions']],
            'ips_polls' => ['fof-polls', ['polls', 'poll_options', 'poll_votes']],
            'ips_profiles' => ['fof-masquerade', ['fof_masquerade_fields', 'fof_masquerade_answers']],
            'ips_signatures' => ['fof-signature', []],
        ];
        foreach ($optional as $configKey => [$extension, $tables]) {
            if (empty($ctx->cfg[$configKey])) {
                continue;
            }
            if (! in_array($extension, $enabled, true)) {
                throw new \RuntimeException("IPS preflight failed: selected extension {$extension} is not enabled.");
            }
            foreach ($tables as $table) {
                if (! Dst::hasTable($table)) {
                    throw new \RuntimeException("IPS preflight failed: selected extension table {$table} is missing.");
                }
            }
        }
        $optionalSource = [
            'ips_reactions' => ['core_reactions', 'core_reputation_index'],
            'ips_polls' => ['core_polls', 'core_voters'],
            'ips_profiles' => ['core_pfields_data', 'core_pfields_content'],
        ];
        foreach ($optionalSource as $configKey => $tables) {
            if (empty($ctx->cfg[$configKey])) {
                continue;
            }
            foreach ($tables as $table) {
                if (! $schema->hasTable($table)) {
                    throw new \RuntimeException("IPS preflight failed: selected source table {$table} is missing.");
                }
            }
        }
        IpsAssets::validateConfig($ctx->cfg);
        $attachmentMissing = $attachmentUnsupported = 0;
        $attachmentCursor = 0;
        do {
            $attachments = self::selectedAttachments($conn)->distinct()->where('a.attach_id', '>', $attachmentCursor)
                ->orderBy('a.attach_id')->limit(500)->get(self::attachmentColumns());
            foreach ($attachments as $attachment) {
                $attachmentCursor = (int) $attachment->attach_id;
                try {
                    IpsAssets::inspectAttachment($ctx->cfg, $attachment);
                } catch (IpsAssetUnavailable $error) {
                    $attachmentMissing++;
                    $ctx->diagnostic('warning', 'ips_attachment_unavailable', $error->getMessage(), 'attachment', $attachment->attach_id);
                }
            }
        } while (count($attachments) === 500);
        if ($attachmentMissing > 0 || $attachmentUnsupported > 0) {
            $ctx->diagnostic('warning', 'ips_preflight_attachment_inventory', 'IPS preflight found attachments that cannot be imported.', null, null, null, ['unavailable' => $attachmentMissing, 'unsupported' => $attachmentUnsupported]);
        }

        $language = $conn->table('core_sys_lang')->where('lang_id', 1)->first(['lang_short', 'lang_title']);
        if (! $language) {
            throw new \RuntimeException('IPS preflight failed: configured language ID 1 is unavailable.');
        }
        if ((string) $language->lang_short !== 'en_NZ.UTF-8') {
            $ctx->diagnostic('warning', 'ips_language_not_en_nz', 'Configured IPS language ID 1 is not English (NZ).', null, null, null, ['language' => (string) $language->lang_short]);
        }
        foreach ([2, 4] as $groupId) {
            if (! $conn->table('core_groups')->where('g_id', $groupId)->exists()) {
                throw new \RuntimeException("IPS preflight failed: required source group {$groupId} is missing.");
            }
        }
        foreach ([1, 2, 3] as $groupId) {
            if (! Dst::db()->table('groups')->where('id', $groupId)->exists()) {
                throw new \RuntimeException("IPS preflight failed: required target group {$groupId} is missing.");
            }
        }

        $forums = $conn->table('forums_forums')->get()->keyBy('id');
        $permissions = $conn->table('core_permission_index')->where('app', 'forums')->where('perm_type', 'forum')->get()->keyBy('perm_type_id');
        foreach ($forums as $forum) {
            if (! isset($permissions[(int) $forum->id])) {
                throw new \RuntimeException("IPS preflight failed: forum {$forum->id} has no permission row.");
            }
        }
        self::orderedForums($forums);

        $selectedForumIds = (clone self::selectedTopics($conn))->distinct()->pluck('t.forum_id')->map(fn ($id) => (int) $id)->all();
        $accessForumIds = [];
        foreach ($selectedForumIds as $forumId) {
            foreach (self::forumAncestors($forumId, $forums) as $ancestorId) {
                $accessForumIds[$ancestorId] = true;
            }
        }
        foreach (array_keys($accessForumIds) as $forumId) {
            $forum = $forums[$forumId];
            if ((int) ($forum->min_posts_view ?? 0) !== 0) {
                throw new \RuntimeException("IPS preflight failed: selected content depends on forum {$forumId}, which has an unrepresentable minimum-post view rule.");
            }
            if (trim((string) ($forum->password ?? '')) !== '') {
                throw new \RuntimeException("IPS preflight failed: selected content depends on password-protected forum {$forumId}.");
            }
        }
        foreach ($selectedForumIds as $forumId) {
            $forum = $forums[$forumId];
            if ((int) ($forum->min_posts_post ?? 0) !== 0) {
                throw new \RuntimeException("IPS preflight failed: selected forum {$forumId} has an unrepresentable minimum-post posting rule.");
            }
            if ((int) ($forum->permission_showtopic ?? 0) !== 0) {
                throw new \RuntimeException("IPS preflight failed: selected forum {$forumId} uses title-only topic visibility.");
            }
        }

        $sourceGroups = $conn->table('core_groups')->get()->keyBy('g_id');
        foreach ($selectedForumIds as $forumId) {
            if ((int) ($forums[$forumId]->can_view_others ?? 1) !== 0) {
                continue;
            }
            foreach ($sourceGroups as $group) {
                $groupId = (int) $group->g_id;
                if ($groupId !== 4 && self::canReadForum($groupId, $forumId, $forums, $permissions, $sourceGroups)) {
                    throw new \RuntimeException("IPS preflight failed: author-only forum {$forumId} is readable by non-administrators.");
                }
            }
        }

        $explicit = self::explicitUserMappings($ctx->cfg);
        foreach ($explicit as $sourceId => $targetId) {
            if (! $conn->table('core_members')->where('member_id', $sourceId)->exists()) {
                throw new \RuntimeException("IPS preflight failed: explicit source member {$sourceId} does not exist.");
            }
            if (! Dst::db()->table('users')->where('id', $targetId)->exists()) {
                throw new \RuntimeException("IPS preflight failed: explicit target user {$targetId} does not exist.");
            }
        }
        if (count($explicit) !== count(array_unique($explicit))) {
            throw new \RuntimeException('IPS preflight failed: multiple source members map to one target user.');
        }

        $duplicateSourceEmail = $conn->table('core_members')->where('member_id', '>', 0)->whereRaw("TRIM(email) <> ''")
            ->selectRaw('LOWER(TRIM(email)) AS normalized_email, COUNT(*) AS aggregate')->groupByRaw('LOWER(TRIM(email))')->havingRaw('COUNT(*) > 1')->first();
        if ($duplicateSourceEmail) {
            throw new \RuntimeException('IPS preflight failed: duplicate source member emails require an explicit data decision.');
        }
        $targetEmails = [];
        foreach (Dst::db()->table('users')->get(['id', 'email']) as $user) {
            $targetEmails[mb_strtolower(trim((string) $user->email))] = (int) $user->id;
        }
        foreach ($conn->table('core_members')->where('member_id', '>', 0)->get(['member_id', 'email']) as $member) {
            $sourceId = (int) $member->member_id;
            $targetId = $targetEmails[mb_strtolower(trim((string) $member->email))] ?? null;
            if ($targetId !== null && ($explicit[$sourceId] ?? null) !== $targetId) {
                throw new \RuntimeException("IPS preflight failed: source member {$sourceId} has an unapproved target email collision.");
            }
        }

        foreach ($sourceGroups as $group) {
            if ((int) $group->g_id !== 4 && ((int) ($group->g_edit_topic ?? 0) !== 0 || (int) ($group->g_open_close_posts ?? 0) !== 0 || (int) ($group->g_post_closed ?? 0) !== 0)) {
                $ctx->diagnostic('warning', 'ips_moderation_capabilities_deferred', 'IPS moderation capabilities have no exact core permission mapping and require review.', 'group', $group->g_id);
            }
        }

        $approved = (int) $conn->table('forums_topics')->where('approved', 1)->count();
        $selected = (int) self::selectedTopics($conn)->count();
        $targetUserCount = (int) Dst::db()->table('users')->count();
        $ctx->diagnostic('info', 'ips_preflight_target_users', 'IPS preflight inventoried existing target users.', null, null, null, ['target_users' => $targetUserCount, 'explicit_mappings' => count($explicit)]);
        if ($approved > $selected) {
            $ctx->diagnostic('info', 'ips_preflight_topic_selection', 'IPS preflight excluded approved topics that did not satisfy the selection rules.', null, null, null, ['approved' => $approved, 'selected' => $selected, 'excluded' => $approved - $selected]);
        }
    }

    private static function explicitUserMappings(array $cfg): array
    {
        $raw = $cfg['ips_user_mappings'] ?? $cfg['user_mappings'] ?? [];
        if (is_string($raw)) {
            $raw = json_decode($raw, true) ?: [];
        }
        if (! is_array($raw)) {
            throw new \RuntimeException('IPS explicit user mappings must be an object of source IDs to target IDs.');
        }

        $out = [];
        foreach ($raw as $sourceId => $targetId) {
            if ((int) $sourceId <= 0 || (int) $targetId <= 0) {
                throw new \RuntimeException('IPS explicit user mappings contain an invalid ID.');
            }
            $out[(int) $sourceId] = (int) $targetId;
        }

        return $out;
    }

    private static function normalizeUsername(?string $name, int $sourceId): string
    {
        $ascii = Str::ascii(trim((string) $name));
        $username = preg_replace('/[^A-Za-z0-9_-]+/', '_', $ascii) ?? '';
        $username = trim($username, '_-');
        if ($username === '' || strlen($username) < 3 || ctype_digit($username)) {
            $username = 'user_' . $username;
        }
        $username = substr($username, 0, 30);

        return trim($username, '_-') !== '' ? $username : ('user_' . $sourceId);
    }

    private static function memberGroupIds($member): array
    {
        $ids = [(int) $member->member_group_id];
        foreach (preg_split('/\s*,\s*/', trim((string) ($member->mgroup_others ?? '')), -1, PREG_SPLIT_NO_EMPTY) ?: [] as $id) {
            if (ctype_digit($id)) {
                $ids[] = (int) $id;
            }
        }

        return array_values(array_unique(array_filter($ids, fn ($id) => $id > 0)));
    }

    private static function groupWords($conn, array $ids): array
    {
        if (! $ids) {
            return [];
        }
        $keys = array_map(fn ($id) => 'core_group_' . (int) $id, $ids);
        $out = [];
        foreach ($conn->table('core_sys_lang_words')->where('lang_id', 1)->where('word_app', 'core')->whereIn('word_key', $keys)->get() as $word) {
            $value = trim((string) (($word->word_custom !== null && $word->word_custom !== '') ? $word->word_custom : $word->word_default));
            if ($value !== '' && preg_match('/^core_group_(\d+)$/', $word->word_key, $match)) {
                $out[(int) $match[1]] = strip_tags($value);
            }
        }

        return $out;
    }

    private static function groupColor($group): ?string
    {
        if (preg_match('/color\s*:\s*(#[0-9a-fA-F]{3,8}|[a-zA-Z]+)/', (string) ($group->prefix ?? ''), $match)) {
            return $match[1];
        }

        return null;
    }

    /** @return array{0:array<int>,1:array<int,int>,2:array<int,int>} */
    private static function orderedForums($forums): array
    {
        $children = [];
        foreach ($forums as $forum) {
            $parentId = (int) ($forum->parent_id ?? -1);
            if ($parentId > 0 && ! isset($forums[$parentId])) {
                throw new \RuntimeException("IPS forum {$forum->id} has missing parent {$parentId}.");
            }
            $children[$parentId][] = $forum;
        }
        foreach ($children as &$siblings) {
            usort($siblings, fn ($a, $b) => [(int) $a->position, (int) $a->id] <=> [(int) $b->position, (int) $b->id]);
        }
        unset($siblings);

        $order = $roots = $positions = [];
        $walk = function ($forum, int $rootId, array $trail) use (&$walk, &$order, &$roots, &$positions, $children) {
            $id = (int) $forum->id;
            if (isset($trail[$id])) {
                throw new \RuntimeException("IPS forum hierarchy contains a cycle at forum {$id}.");
            }
            $trail[$id] = true;
            $order[] = $id;
            $roots[$id] = $rootId;
            $positions[$id] = count(array_filter($roots, fn ($value) => $value === $rootId)) - 1;
            foreach ($children[$id] ?? [] as $child) {
                $walk($child, $rootId, $trail);
            }
        };
        foreach ($children[-1] ?? [] as $index => $root) {
            $walk($root, (int) $root->id, []);
            $positions[(int) $root->id] = $index;
        }

        if (count($order) !== count($forums)) {
            throw new \RuntimeException('IPS forum hierarchy contains a cycle or has no top-level root.');
        }

        return [$order, $roots, $positions];
    }

    private static function isRedirectForum($forum): bool
    {
        return (int) ($forum->redirect_on ?? 0) === 1 && trim((string) ($forum->redirect_url ?? '')) !== '';
    }

    private static function forumRootIds($conn, array $forumIds): array
    {
        $forums = $conn->table('forums_forums')->get()->keyBy('id');
        [, $roots] = self::orderedForums($forums);

        return array_intersect_key($roots, array_flip(array_map('intval', $forumIds)));
    }

    private static function permissionAllows(?string $permission, int $groupId): bool
    {
        $permission = trim((string) $permission);
        if ($permission === '*') {
            return true;
        }
        if ($permission === '') {
            return false;
        }

        return in_array($groupId, array_map('intval', preg_split('/\s*,\s*/', $permission, -1, PREG_SPLIT_NO_EMPTY) ?: []), true);
    }

    private static function forumAncestors(int $forumId, $forums): array
    {
        $ids = [];
        $seen = [];
        while ($forumId > 0 && isset($forums[$forumId])) {
            if (isset($seen[$forumId])) {
                throw new \RuntimeException("IPS forum hierarchy contains a cycle at forum {$forumId}.");
            }
            $seen[$forumId] = true;
            $ids[] = $forumId;
            $forumId = (int) ($forums[$forumId]->parent_id ?? -1);
        }

        return $ids;
    }

    private static function canSeeForum(int $groupId, int $forumId, $forums, $permissions, $groups): bool
    {
        if (! isset($groups[$groupId]) || (int) ($groups[$groupId]->g_view_board ?? 0) !== 1) {
            return false;
        }
        foreach (self::forumAncestors($forumId, $forums) as $ancestorId) {
            if (! isset($permissions[$ancestorId]) || ! self::permissionAllows($permissions[$ancestorId]->perm_view ?? null, $groupId)) {
                return false;
            }
        }

        return true;
    }

    private static function canReadForum(int $groupId, int $forumId, $forums, $permissions, $groups): bool
    {
        return self::canSeeForum($groupId, $forumId, $forums, $permissions, $groups)
            && self::permissionAllows($permissions[$forumId]->perm_2 ?? null, $groupId);
    }

    private static function importPermissions(Ctx $ctx): void
    {
        $conn = $ctx->src();
        $forums = $conn->table('forums_forums')->get()->keyBy('id');
        $groups = $conn->table('core_groups')->get()->keyBy('g_id');
        $permissions = $conn->table('core_permission_index')->where('app', 'forums')->where('perm_type', 'forum')->get()->keyBy('perm_type_id');
        [, $roots] = self::orderedForums($forums);
        $groupMap = $ctx->mapGet('group', $groups->keys()->all());
        $tagMap = $ctx->mapGet('tag', $forums->keys()->all());
        $grants = [];

        foreach ($groups as $group) {
            $sourceGroupId = (int) $group->g_id;
            $targetGroupId = $groupMap[(string) $sourceGroupId] ?? null;
            if (! $targetGroupId) {
                throw new \RuntimeException("IPS group {$sourceGroupId} is not mapped.");
            }

            $readable = [];
            foreach ($forums as $forum) {
                $forumId = (int) $forum->id;
                if (isset($tagMap[(string) $forumId]) && self::canReadForum($sourceGroupId, $forumId, $forums, $permissions, $groups)) {
                    $readable[$forumId] = true;
                }
            }
            $reachableRoots = [];
            foreach (array_keys($readable) as $forumId) {
                $reachableRoots[$roots[$forumId]] = true;
            }

            foreach ($forums as $forum) {
                $forumId = (int) $forum->id;
                $tagId = $tagMap[(string) $forumId] ?? null;
                if (! $tagId) {
                    continue;
                }
                $isRoot = $roots[$forumId] === $forumId;
                if (isset($readable[$forumId]) || ($isRoot && isset($reachableRoots[$forumId]))) {
                    $grants[$targetGroupId][] = 'tag' . $tagId . '.viewForum';
                }
                if (! isset($readable[$forumId])) {
                    continue;
                }
                $row = $permissions[$forumId];
                if ((int) ($forum->sub_can_post ?? 1) === 1 && self::permissionAllows($row->perm_3 ?? null, $sourceGroupId)) {
                    $grants[$targetGroupId][] = 'tag' . $tagId . '.startDiscussion';
                }
                if (self::permissionAllows($row->perm_4 ?? null, $sourceGroupId)) {
                    $grants[$targetGroupId][] = 'tag' . $tagId . '.discussion.reply';
                }
                if (self::permissionAllows($row->perm_5 ?? null, $sourceGroupId)) {
                    $grants[$targetGroupId][] = 'tag' . $tagId . '.fof-upload.download';
                    $grants[$targetGroupId][] = 'fof-upload.download';
                }
            }
            foreach (array_keys($readable) as $forumId) {
                $rootId = $roots[$forumId];
                if ($rootId === $forumId || ! isset($tagMap[(string) $rootId])) {
                    continue;
                }
                $row = $permissions[$forumId];
                $rootTagId = $tagMap[(string) $rootId];
                if ((int) ($forums[$forumId]->sub_can_post ?? 1) === 1 && self::permissionAllows($row->perm_3 ?? null, $sourceGroupId)) {
                    $grants[$targetGroupId][] = 'tag' . $rootTagId . '.startDiscussion';
                }
                if (self::permissionAllows($row->perm_4 ?? null, $sourceGroupId)) {
                    $grants[$targetGroupId][] = 'tag' . $rootTagId . '.discussion.reply';
                }
                if (self::permissionAllows($row->perm_5 ?? null, $sourceGroupId)) {
                    $grants[$targetGroupId][] = 'tag' . $rootTagId . '.fof-upload.download';
                }
            }
            if ((int) ($group->g_attach_max ?? 0) !== 0) {
                $grants[$targetGroupId][] = 'fof-upload.upload';
            }
        }

        self::addModeratorGrants($conn, $groupMap, $tagMap, $roots, $grants, $ctx);

        self::validatePermissionMatrix($conn, $forums, $groups, $permissions, $roots, $groupMap, $tagMap, $grants);
        Dst::replaceIpsPermissions(array_merge(array_values($groupMap), [3]), array_values($tagMap), $grants);
        Dst::flushPermissionCache();
    }

    private static function addModeratorGrants($conn, array $groupMap, array $tagMap, array $roots, array &$grants, Ctx $ctx): void
    {
        $abilityMap = [
            'can_edit_topic' => 'discussion.rename',
            'can_pin_topic' => 'discussion.sticky',
            'can_lock_topic' => 'discussion.lock',
            'can_edit_post' => 'discussion.editPosts',
            'can_hide_topic' => 'discussion.hide',
            'can_hide_post' => 'discussion.hidePosts',
            'can_move_topic' => 'discussion.tag',
        ];
        foreach ($conn->table('core_moderators')->where('type', 'g')->get(['id', 'perms']) as $moderator) {
            $sourceGroupId = (int) $moderator->id;
            if ($sourceGroupId === 4 || ! isset($groupMap[(string) $sourceGroupId])) {
                continue;
            }
            $perms = self::decodeStructured((string) $moderator->perms);
            if (! is_array($perms)) {
                $ctx->diagnostic('warning', 'ips_moderator_permissions_invalid', 'Deferred invalid IPS moderator permissions.', 'group', $sourceGroupId);
                continue;
            }
            $forums = array_values(array_unique(array_map('intval', array_keys(is_array($perms['forums'] ?? null) ? $perms['forums'] : []))));
            $targetGroupId = $groupMap[(string) $sourceGroupId];
            foreach ($forums as $forumId) {
                $tagId = $tagMap[(string) $forumId] ?? null;
                $rootTagId = isset($roots[$forumId]) ? ($tagMap[(string) $roots[$forumId]] ?? null) : null;
                if (! $tagId || ! $rootTagId) {
                    continue;
                }
                foreach ($abilityMap as $sourceAbility => $targetAbility) {
                    if (! empty($perms[$sourceAbility])) {
                        $grants[$targetGroupId][] = 'tag' . $tagId . '.' . $targetAbility;
                        $grants[$targetGroupId][] = 'tag' . $rootTagId . '.' . $targetAbility;
                    }
                }
            }
            $ctx->diagnostic('info', 'ips_moderator_permissions_mapped', 'Mapped supported IPS moderator capabilities; unsupported capabilities remain deferred.', 'group', $sourceGroupId);
        }
    }

    private static function validatePermissionMatrix($conn, $forums, $groups, $permissions, array $roots, array $groupMap, array $tagMap, array $grants): void
    {
        $granted = [];
        foreach ($grants as $targetGroupId => $items) {
            $granted[(int) $targetGroupId] = array_fill_keys($items, true);
        }
        $selectedForumIds = array_fill_keys(self::selectedTopics($conn)->distinct()->pluck('t.forum_id')->map(fn ($id) => (int) $id)->all(), true);

        foreach ($groups as $group) {
            $sourceGroupId = (int) $group->g_id;
            if ($sourceGroupId === 4) {
                continue;
            }
            $targetGroupId = $groupMap[(string) $sourceGroupId];
            $effective = ($granted[2] ?? []) + ($granted[$targetGroupId] ?? []);
            $actualUpload = isset($effective['fof-upload.upload']);
            $expectedUpload = (int) ($group->g_attach_max ?? 0) !== 0;
            if ($actualUpload !== $expectedUpload) {
                throw new \RuntimeException("IPS permission preflight failed for group {$sourceGroupId}, global upload ability.");
            }
            foreach ($forums as $forum) {
                $forumId = (int) $forum->id;
                if (! isset($selectedForumIds[$forumId]) || ! isset($tagMap[(string) $forumId])) {
                    continue;
                }
                $rootId = $roots[$forumId];
                $tagId = $tagMap[(string) $forumId];
                $rootTagId = $tagMap[(string) $rootId];
                $row = $permissions[$forumId];
                $expected = [
                    'viewForum' => self::canReadForum($sourceGroupId, $forumId, $forums, $permissions, $groups),
                    'startDiscussion' => self::canReadForum($sourceGroupId, $forumId, $forums, $permissions, $groups) && (int) ($forum->sub_can_post ?? 1) === 1 && self::permissionAllows($row->perm_3 ?? null, $sourceGroupId),
                    'discussion.reply' => self::canReadForum($sourceGroupId, $forumId, $forums, $permissions, $groups) && self::permissionAllows($row->perm_4 ?? null, $sourceGroupId),
                    'fof-upload.download' => self::canReadForum($sourceGroupId, $forumId, $forums, $permissions, $groups) && self::permissionAllows($row->perm_5 ?? null, $sourceGroupId),
                ];
                foreach ($expected as $ability => $allowed) {
                    $actual = isset($effective['tag' . $tagId . '.' . $ability]) && ($tagId === $rootTagId || isset($effective['tag' . $rootTagId . '.' . $ability]));
                    if ($actual !== $allowed) {
                        throw new \RuntimeException("IPS permission preflight failed for group {$sourceGroupId}, forum {$forumId}, ability {$ability}.");
                    }
                }
            }
        }
    }

    private static function postsBatch($cursor, int $limit, Ctx $ctx): array
    {
        $cur = is_array($cursor) ? $cursor : ['tid' => 0, 'rank' => 0, 'at' => 0, 'pid' => 0, 'num' => 0];
        // Restrict the expensive computed ordering to the current topic plus
        // enough following topics to guarantee a full page of visible posts.
        $topicIds = self::selectedTopics($ctx->src())
            ->where('t.tid', '>=', (int) $cur['tid'])
            ->orderBy('t.tid')->limit($limit + 1)->pluck('t.tid')->all();
        $query = self::selectedPosts($ctx->src())->whereIn('p.topic_id', $topicIds)->where(function ($query) use ($cur) {
            $query->where('p.topic_id', '>', (int) $cur['tid'])
                ->orWhere(function ($query) use ($cur) {
                    $query->where('p.topic_id', (int) $cur['tid'])->where(function ($query) use ($cur) {
                        $query->whereRaw('(CASE WHEN p.pid = t.topic_firstpost THEN 0 ELSE 1 END) > ?', [(int) ($cur['rank'] ?? 0)])
                            ->orWhere(function ($query) use ($cur) {
                                $query->whereRaw('(CASE WHEN p.pid = t.topic_firstpost THEN 0 ELSE 1 END) = ?', [(int) ($cur['rank'] ?? 0)])
                                    ->where(function ($query) use ($cur) {
                                        $query->whereRaw('COALESCE(p.post_date, 0) > ?', [(int) $cur['at']])
                                            ->orWhere(function ($query) use ($cur) {
                                                $query->whereRaw('COALESCE(p.post_date, 0) = ?', [(int) $cur['at']])->where('p.pid', '>', (int) $cur['pid']);
                                            });
                                    });
                            });
                    });
                });
        });
        $rows = $query->orderBy('p.topic_id')->orderByRaw('CASE WHEN p.pid = t.topic_firstpost THEN 0 ELSE 1 END')->orderByRaw('COALESCE(p.post_date, 0)')->orderBy('p.pid')->limit($limit)
            ->get(['p.pid', 'p.topic_id', 'p.author_id', 'p.author_name', 'p.post_date', 'p.post', 't.starter_name', 't.topic_firstpost']);
        $topicMap = $ctx->mapGet('topic', $rows->pluck('topic_id')->all());
        $userMap = $ctx->mapGet('user', $rows->pluck('author_id')->all());
        $attachmentRows = $ctx->src()->table('core_attachments_map as am')->join('core_attachments as a', 'a.attach_id', '=', 'am.attachment_id')
            ->where('am.location_key', 'forums_Forums')->whereIn('am.id2', $rows->pluck('pid')->all())
            ->orderBy('a.attach_id')->get(array_merge(self::attachmentColumns(), ['am.id2 as mapped_post_id']));
        $attachmentsByPost = [];
        foreach ($attachmentRows as $attachment) {
            $attachmentsByPost[(int) $attachment->mapped_post_id][(int) $attachment->attach_id] ??= $attachment;
        }
        $postMap = [];
        $n = 0;

        foreach ($rows as $post) {
            $topicId = (int) $post->topic_id;
            if ($topicId !== (int) $cur['tid']) {
                $cur['num'] = 0;
            }
            $cur['tid'] = $topicId;
            $cur['rank'] = (int) $post->pid === (int) $post->topic_firstpost ? 0 : 1;
            $cur['at'] = (int) ($post->post_date ?? 0);
            $cur['pid'] = (int) $post->pid;
            $discussionId = $topicMap[(string) $topicId] ?? null;
            if (! $discussionId) {
                continue;
            }

            $authorId = (int) $post->author_id;
            $postAttachments = $attachmentsByPost[(int) $post->pid] ?? [];
            [$rawHtml, $inlineAttachmentIds] = IpsAssets::rewriteHtml((string) ($post->post ?? ''), $postAttachments);
            $html = self::ipsHtml($rawHtml);
            if ($authorId === 0) {
                $name = trim((string) ($post->author_name ?: ((int) $post->pid === (int) $post->topic_firstpost ? $post->starter_name : '')));
                if ($name !== '') {
                    $html = '<p><strong>Originally posted by ' . htmlspecialchars(strip_tags($name), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</strong></p>' . $html;
                }
            }
            $targetUserId = $authorId === 0 ? null : ($userMap[(string) $authorId] ?? null);
            if ($authorId !== 0 && $targetUserId === null) {
                $ctx->diagnostic('warning', 'ips_post_author_unmapped', 'Imported IPS post without its unmapped source author.', 'post', $post->pid);
            }
            $number = ++$cur['num'];
            $previews = [];
            $files = [];
            foreach ($postAttachments as $attachmentId => $attachment) {
                $asset = AssetJournal::get($ctx, 'attachment', $attachmentId);
                if (! $asset || ! in_array($asset->state, [AssetJournal::FINALIZED, AssetJournal::LINKED], true)) {
                    $ctx->diagnostic('warning', 'ips_attachment_not_finalized', 'Skipped attachment that was not finalized.', 'attachment', $attachmentId, null, ['post_id' => (int) $post->pid]);
                    continue;
                }
                [$file, $preview] = IpsAssets::linkAttachment($ctx, $attachment, $asset);
                $files[$attachmentId] = $file;
                $previews[$attachmentId] = $preview;
            }
            $markdown = IpsAssets::substitute(Dst::markdown($html), $previews, $inlineAttachmentIds);
            if (str_contains($markdown, 'IPSATTACHMENTTOKEN') || str_contains($markdown, 'fileStore.core_Attachment') || str_contains($markdown, 'data-fileid')) {
                $ctx->diagnostic('warning', 'ips_attachment_markup_unresolved', 'Removed unresolved IPS attachment markup from an imported post.', 'post', $post->pid);
                $markdown = preg_replace('/IPSATTACHMENTTOKEN\d+ENDTOKEN/', '[attachment unavailable]', $markdown) ?? $markdown;
                $markdown = str_replace('fileStore.core_Attachment', '', $markdown);
            }
            $content = Dst::parseMarkdown($markdown);
            $targetPostId = Dst::parsedPost($discussionId, $number, $targetUserId, $content, Src::ts($post->post_date));
            $postMap[(int) $post->pid] = $targetPostId;
            foreach ($files as $file) {
                IpsAssets::attachToPost((int) $file->id, $targetPostId);
            }
            $n++;
        }
        $ctx->mapPut('post', $postMap);

        return ['cursor' => $cur, 'processed' => count($rows), 'done' => count($rows) < $limit, 'summary' => ['posts' => $n]];
    }

    private static function avatarsBatch($cursor, int $limit, Ctx $ctx): array
    {
        $rows = $ctx->src()->table('core_members')->where('member_id', '>', (int) $cursor)->where('pp_photo_type', 'custom')
            ->orderBy('member_id')->limit($limit)->get(['member_id', 'pp_main_photo', 'pp_thumb_photo']);
        $userMap = $ctx->mapGet('user', $rows->pluck('member_id')->all());
        $imported = $skipped = 0;
        foreach ($rows as $member) {
            $cursor = (int) $member->member_id;
            $userId = $userMap[(string) $member->member_id] ?? null;
            if (! $userId) {
                $skipped++;
                continue;
            }
            $relative = trim((string) ($member->pp_main_photo ?: $member->pp_thumb_photo));
            if ($relative === '') {
                $ctx->diagnostic('warning', 'ips_avatar_no_path', 'Custom IPS avatar has no source path.', 'user', $member->member_id, $userId);
                $skipped++;
                continue;
            }
            try {
                self::writeAvatar($ctx, $userId, (int) $member->member_id, $relative);
                $imported++;
            } catch (\Throwable $error) {
                $ctx->diagnostic('warning', 'ips_avatar_failed', $error->getMessage(), 'user', $member->member_id, $userId);
                $skipped++;
            }
        }

        return ['cursor' => (int) $cursor, 'processed' => count($rows), 'done' => count($rows) < $limit, 'summary' => ['avatars' => $imported, 'skipped' => $skipped]];
    }

    private static function writeAvatar(Ctx $ctx, int $userId, int $sourceId, string $relative): void
    {
        $managerClass = 'Intervention\\Image\\ImageManager';
        $filesystemClass = 'Illuminate\\Contracts\\Filesystem\\Factory';
        if (! class_exists($managerClass)) {
            throw new \RuntimeException('Flarum image processing is unavailable for avatar import.');
        }
        $source = IpsAssets::sourcePath($ctx->cfg, $relative);
        $manager = resolve($managerClass);
        $image = $manager->read($source);
        $width = $image->width();
        $height = $image->height();
        $animated = $image->isAnimated();
        $extension = $animated ? 'gif' : 'webp';
        $base = 'ips-' . $ctx->runId . '-' . $sourceId;
        $disk = resolve($filesystemClass)->disk('flarum-avatars');
        $generated = [];
        foreach (['' => 100, '@2x' => 200, '@3x' => 300] as $suffix => $size) {
            if ($suffix !== '' && ($width < $size || $height < $size)) {
                continue;
            }
            $resized = clone $image;
            $resized->cover($size, $size);
            $path = $base . $suffix . '.' . $extension;
            if (! $disk->put($path, $animated ? $resized->toGif() : $resized->toWebp())) {
                throw new \RuntimeException("Could not write avatar variant for IPS member {$sourceId}.");
            }
            $generated[$suffix] = true;
        }
        Dst::db()->table('users')->where('id', $userId)->update([
            'avatar_url' => $base . '.' . $extension,
            'has_avatar_2x' => isset($generated['@2x']),
            'has_avatar_3x' => isset($generated['@3x']),
        ]);
    }

    private static function importReactionDefinitions(Ctx $ctx): void
    {
        if (! Dst::hasTable('reactions') || ! Dst::hasTable('post_reactions')) {
            throw new \RuntimeException('FoF Reactions tables are unavailable.');
        }
        $definitions = [
            1 => ['thumbsup', 'Thumbs up'],
            3 => ['joy', 'Tears of joy'],
            4 => ['hushed', 'Hushed'],
            5 => ['cry', 'Crying'],
            8 => ['heart', 'Heart'],
            9 => ['angry', 'Angry'],
        ];
        $map = [];
        foreach ($definitions as $sourceId => [$identifier, $display]) {
            $targetId = Dst::db()->table('reactions')->where('identifier', $identifier)->value('id');
            if (! $targetId) {
                $targetId = Dst::db()->table('reactions')->insertGetId([
                    'identifier' => $identifier,
                    'type' => 'emoji',
                    'enabled' => 1,
                    'display' => $display,
                ]);
            } else {
                Dst::db()->table('reactions')->where('id', $targetId)->update(['type' => 'emoji', 'enabled' => 1, 'display' => $display]);
            }
            $map[$sourceId] = (int) $targetId;
        }
        $ctx->mapPut('reaction', $map);
    }

    private static function reactionsBatch($cursor, int $limit, Ctx $ctx): array
    {
        $rows = $ctx->src()->table('core_reputation_index')->where('id', '>', (int) $cursor)
            ->where('rep_class', 'IPS\\forums\\Topic\\Post')->whereIn('reaction', [1, 3, 4, 5, 8, 9])
            ->orderBy('id')->limit($limit)->get(['id', 'member_id', 'type_id', 'rep_date', 'reaction']);
        $postMap = $ctx->mapGet('post', $rows->pluck('type_id')->all());
        $userMap = $ctx->mapGet('user', $rows->pluck('member_id')->all());
        $reactionMap = $ctx->mapGet('reaction', $rows->pluck('reaction')->all());
        $imported = $skipped = 0;
        foreach ($rows as $row) {
            $cursor = (int) $row->id;
            $postId = $postMap[(string) $row->type_id] ?? null;
            $userId = $userMap[(string) $row->member_id] ?? null;
            $reactionId = $reactionMap[(string) $row->reaction] ?? null;
            if (! $postId || ! $userId || ! $reactionId) {
                $ctx->diagnostic('info', 'ips_reaction_unmapped', 'Excluded IPS reaction whose post, actor, or definition was not mapped.', 'reaction', $row->id);
                $skipped++;
                continue;
            }
            if (Dst::db()->table('post_reactions')->where('post_id', $postId)->where('user_id', $userId)->whereNotNull('reaction_id')->exists()) {
                $ctx->diagnostic('warning', 'ips_reaction_duplicate', 'Excluded duplicate target post/user reaction.', 'reaction', $row->id, $postId);
                $skipped++;
                continue;
            }
            $at = Carbon::createFromTimestamp(max(1, (int) $row->rep_date));
            Dst::db()->table('post_reactions')->insert([
                'post_id' => $postId,
                'user_id' => $userId,
                'reaction_id' => $reactionId,
                'created_at' => $at,
                'updated_at' => $at,
            ]);
            $imported++;
        }

        return ['cursor' => (int) $cursor, 'processed' => count($rows), 'done' => count($rows) < $limit, 'summary' => ['reactions' => $imported, 'skipped' => $skipped]];
    }

    private static function pollsBatch($cursor, int $limit, Ctx $ctx): array
    {
        foreach (['polls', 'poll_options', 'poll_votes'] as $table) {
            if (! Dst::hasTable($table)) {
                throw new \RuntimeException('FoF Polls tables are unavailable.');
            }
        }
        $rows = $ctx->src()->table('core_polls')->where('pid', '>', max(1, (int) $cursor))
            ->whereNotIn('choices', ['false', '0', ''])->orderBy('pid')->limit($limit)->get();
        $imported = $votesImported = $skipped = 0;
        foreach ($rows as $sourcePoll) {
            $cursor = (int) $sourcePoll->pid;
            $topic = $ctx->src()->table('forums_topics')->where('poll_state', (string) $sourcePoll->pid)->first(['tid', 'topic_firstpost', 'starter_id']);
            if (! $topic) {
                $ctx->diagnostic('info', 'ips_poll_topic_unmapped', 'Excluded IPS poll without a source topic.', 'poll', $sourcePoll->pid);
                $skipped++;
                continue;
            }
            $postMap = $ctx->mapGet('post', [(int) $topic->topic_firstpost]);
            $userMap = $ctx->mapGet('user', [(int) $sourcePoll->starter_id]);
            $postId = $postMap[(string) $topic->topic_firstpost] ?? null;
            if (! $postId) {
                $ctx->diagnostic('info', 'ips_poll_post_unmapped', 'Excluded IPS poll whose discussion first post was not imported.', 'poll', $sourcePoll->pid);
                $skipped++;
                continue;
            }
            $questions = self::decodeStructured((string) $sourcePoll->choices);
            if (! is_array($questions) || ! $questions) {
                $ctx->diagnostic('warning', 'ips_poll_choices_invalid', 'Deferred IPS poll with unavailable or invalid choices.', 'poll', $sourcePoll->pid);
                $skipped++;
                continue;
            }
            $sourceVotes = $ctx->src()->table('core_voters')->where('poll', $sourcePoll->pid)->orderBy('vid')->get();
            foreach ($questions as $questionKey => $question) {
                if (! is_array($question) || ! is_array($question['choice'] ?? null)) {
                    $ctx->diagnostic('warning', 'ips_poll_question_invalid', 'Deferred invalid IPS poll question.', 'poll', $sourcePoll->pid, null, ['question' => (string) $questionKey]);
                    continue;
                }
                $createdAt = Carbon::createFromTimestamp(max(1, (int) $sourcePoll->start_date));
                $endDate = (int) $sourcePoll->poll_close_date > 0 ? Carbon::createFromTimestamp((int) $sourcePoll->poll_close_date) : null;
                $pollId = (int) Dst::db()->table('polls')->insertGetId([
                    'question' => Str::limit((string) ($question['question'] ?? $sourcePoll->poll_question ?: 'Poll'), 255, ''),
                    'subtitle' => null,
                    'image' => null,
                    'image_alt' => null,
                    'post_id' => $postId,
                    'user_id' => $userMap[(string) $sourcePoll->starter_id] ?? null,
                    'end_date' => $endDate,
                    'published_at' => $createdAt,
                    'created_at' => $createdAt,
                    'updated_at' => $createdAt,
                    'vote_count' => 0,
                    'settings' => json_encode([
                        'public_poll' => (bool) $sourcePoll->poll_view_voters,
                        'allow_multiple_votes' => (bool) ($question['multi'] ?? false),
                        'max_votes' => 0,
                        'hide_votes' => false,
                        'allow_change_vote' => false,
                    ]),
                    'poll_group_id' => null,
                ]);
                $ctx->mapPut('poll', [$sourcePoll->pid . ':' . $questionKey => $pollId]);
                $optionMap = [];
                foreach ($question['choice'] as $optionKey => $answer) {
                    $optionId = (int) Dst::db()->table('poll_options')->insertGetId([
                        'answer' => Str::limit(strip_tags((string) $answer), 255, ''),
                        'poll_id' => $pollId,
                        'created_at' => $createdAt,
                        'updated_at' => $createdAt,
                        'vote_count' => 0,
                        'image_url' => null,
                    ]);
                    $optionMap[(string) $optionKey] = $optionId;
                    $ctx->mapPut('poll-option', [$sourcePoll->pid . ':' . $questionKey . ':' . $optionKey => $optionId]);
                }
                $seen = [];
                foreach ($sourceVotes as $sourceVote) {
                    $voterMap = $ctx->mapGet('user', [(int) $sourceVote->member_id]);
                    $userId = $voterMap[(string) $sourceVote->member_id] ?? null;
                    if (! $userId) {
                        continue;
                    }
                    $ballot = self::decodeStructured((string) $sourceVote->member_choices);
                    $selected = is_array($ballot) ? ($ballot[(string) $questionKey] ?? $ballot[(int) $questionKey] ?? null) : null;
                    $selected = is_array($selected) ? $selected : [$selected];
                    foreach ($selected as $optionKey) {
                        $optionKey = (string) $optionKey;
                        if (! isset($optionMap[$optionKey])) {
                            continue;
                        }
                        $key = $userId . ':' . $optionMap[$optionKey];
                        if (isset($seen[$key])) {
                            continue;
                        }
                        $seen[$key] = true;
                        $at = Carbon::createFromTimestamp(max(1, (int) $sourceVote->vote_date));
                        Dst::db()->table('poll_votes')->insert([
                            'poll_id' => $pollId,
                            'option_id' => $optionMap[$optionKey],
                            'user_id' => $userId,
                            'created_at' => $at,
                            'updated_at' => $at,
                        ]);
                        $votesImported++;
                    }
                }
                foreach ($optionMap as $optionId) {
                    Dst::db()->table('poll_options')->where('id', $optionId)->update([
                        'vote_count' => Dst::db()->table('poll_votes')->where('option_id', $optionId)->count(),
                    ]);
                }
                Dst::db()->table('polls')->where('id', $pollId)->update([
                    'vote_count' => Dst::db()->table('poll_votes')->where('poll_id', $pollId)->count(),
                ]);
                $imported++;
            }
        }

        if (count($rows) < $limit) {
            $legacy = (int) $ctx->src()->table('core_voters')->where('poll', 0)->count();
            if ($legacy > 0) {
                $ctx->diagnostic('info', 'ips_legacy_polls_deferred', 'Deferred legacy poll ballots because their option definitions are unavailable.', 'poll', 'legacy', null, ['ballots' => $legacy]);
            }
        }

        return ['cursor' => (int) $cursor, 'processed' => count($rows), 'done' => count($rows) < $limit, 'summary' => ['polls' => $imported, 'poll_votes' => $votesImported, 'skipped' => $skipped]];
    }

    private static function decodeStructured(string $value): mixed
    {
        $value = trim($value);
        if ($value === '') {
            return null;
        }
        $json = json_decode($value, true);
        if (json_last_error() === JSON_ERROR_NONE) {
            return $json;
        }

        return @unserialize($value, ['allowed_classes' => false]);
    }

    private static function importProfileFields(Ctx $ctx): void
    {
        foreach (['fof_masquerade_fields', 'fof_masquerade_answers'] as $table) {
            if (! Dst::hasTable($table)) {
                throw new \RuntimeException('FoF Masquerade tables are unavailable.');
            }
        }
        [$names, $descriptions] = self::profileFieldWords($ctx->src(), [2, 3, 5, 6, 7]);
        $fields = $ctx->src()->table('core_pfields_data')->whereIn('pf_id', [2, 3, 5, 6, 7])->orderBy('pf_position')->get()->keyBy('pf_id');
        $map = [];
        foreach ([2, 3, 5, 6, 7] as $sourceId) {
            $field = $fields[$sourceId] ?? null;
            if (! $field) {
                continue;
            }
            $type = null;
            $validation = null;
            if ($sourceId === 7) {
                $options = self::decodeStructured((string) $field->pf_content);
                if (is_array($options) && ! array_filter($options, fn ($option) => str_contains((string) $option, ','))) {
                    $type = 'select';
                    $validation = 'in:' . implode(',', $options);
                }
            }
            $now = Carbon::now();
            $targetId = (int) Dst::db()->table('fof_masquerade_fields')->insertGetId([
                'name' => Str::limit($names[$sourceId] ?? ('Profile field ' . $sourceId), 255, ''),
                'description' => Str::limit($descriptions[$sourceId] ?? '', 255, ''),
                'required' => 0,
                'validation' => $validation,
                'prefix' => null,
                'icon' => null,
                'sort' => (int) $field->pf_position,
                'on_bio' => $sourceId === 3 ? 1 : 0,
                'type' => $type,
                'created_at' => $now,
                'updated_at' => $now,
                'deleted_at' => null,
            ]);
            $map[$sourceId] = $targetId;
        }
        $ctx->mapPut('profile-field', $map);
    }

    private static function profileAnswersBatch($cursor, int $limit, Ctx $ctx): array
    {
        $rows = $ctx->src()->table('core_pfields_content')->where('member_id', '>', (int) $cursor)->orderBy('member_id')->limit($limit)->get();
        $userMap = $ctx->mapGet('user', $rows->pluck('member_id')->all());
        $fieldMap = $ctx->mapGet('profile-field', [2, 3, 5, 6, 7]);
        $imported = 0;
        foreach ($rows as $row) {
            $cursor = (int) $row->member_id;
            $userId = $userMap[(string) $row->member_id] ?? null;
            if (! $userId) {
                continue;
            }
            foreach ([2, 3, 5, 6, 7] as $sourceFieldId) {
                $targetFieldId = $fieldMap[(string) $sourceFieldId] ?? null;
                $value = trim(strip_tags((string) ($row->{'field_' . $sourceFieldId} ?? '')));
                if ($sourceFieldId === 7 && in_array($value, ['0', '1', '2'], true)) {
                    $value = ['Undisclosed', 'Male', 'Female'][(int) $value];
                }
                if (! $targetFieldId || $value === '') {
                    continue;
                }
                $now = Carbon::now();
                Dst::db()->table('fof_masquerade_answers')->insertOrIgnore([
                    'field_id' => $targetFieldId,
                    'user_id' => $userId,
                    'content' => $value,
                    'created_at' => $now,
                    'updated_at' => $now,
                ]);
                $imported++;
            }
        }

        return ['cursor' => (int) $cursor, 'processed' => count($rows), 'done' => count($rows) < $limit, 'summary' => ['profile_answers' => $imported]];
    }

    private static function signaturesBatch($cursor, int $limit, Ctx $ctx): array
    {
        if (! Dst::hasColumn('users', 'signature')) {
            throw new \RuntimeException('FoF Signature is unavailable.');
        }
        $formatterClass = 'FoF\\Signature\\Formatter\\SignatureFormatter';
        $validatorClass = 'FoF\\Signature\\Validator\\SignatureValidator';
        if (! class_exists($formatterClass) || ! class_exists($validatorClass)) {
            throw new \RuntimeException('FoF Signature formatter or validator is unavailable.');
        }
        $rows = $ctx->src()->table('core_members')->where('member_id', '>', (int) $cursor)
            ->whereRaw("COALESCE(TRIM(signature), '') <> ''")->orderBy('member_id')->limit($limit)->get(['member_id', 'signature']);
        $userMap = $ctx->mapGet('user', $rows->pluck('member_id')->all());
        $formatter = resolve($formatterClass);
        $validator = resolve($validatorClass);
        $imported = $skipped = 0;
        foreach ($rows as $row) {
            $cursor = (int) $row->member_id;
            $userId = $userMap[(string) $row->member_id] ?? null;
            if (! $userId) {
                $skipped++;
                continue;
            }
            $source = Dst::markdown(self::ipsHtml((string) $row->signature));
            try {
                $validator->assertValid(['signature' => $source]);
                $parsed = $formatter->parse($source);
                $formatter->render($parsed);
            } catch (\Throwable $error) {
                $ctx->diagnostic('warning', 'ips_signature_invalid', 'Skipped IPS signature rejected by the target formatter or policy.', 'user', $row->member_id, $userId);
                $skipped++;
                continue;
            }
            Dst::db()->table('users')->where('id', $userId)->update(['signature' => $parsed]);
            $imported++;
        }

        return ['cursor' => (int) $cursor, 'processed' => count($rows), 'done' => count($rows) < $limit, 'summary' => ['signatures' => $imported, 'skipped' => $skipped]];
    }

    private static function profileFieldWords($conn, array $ids): array
    {
        $keys = [];
        foreach ($ids as $id) {
            $keys[] = 'core_pfield_' . $id;
            $keys[] = 'core_pfield_' . $id . '_desc';
        }
        $names = $descriptions = [];
        foreach ($conn->table('core_sys_lang_words')->where('lang_id', 1)->whereIn('word_key', $keys)->get() as $word) {
            $value = trim(strip_tags((string) (($word->word_custom !== null && $word->word_custom !== '') ? $word->word_custom : $word->word_default)));
            if (preg_match('/^core_pfield_(\d+)_desc$/', $word->word_key, $match)) {
                $descriptions[(int) $match[1]] = $value;
            } elseif (preg_match('/^core_pfield_(\d+)$/', $word->word_key, $match)) {
                $names[(int) $match[1]] = $value;
            }
        }

        return [$names, $descriptions];
    }

    /**
     * Forum titles/descriptions are translatable strings in core_sys_lang_words,
     * keyed forums_forum_{id} / forums_forum_{id}_desc.
     *
     * @return array{0:array<int,string>,1:array<int,string>} [names, descs]
     */
    private static function forumWords($conn, array $ids): array
    {
        $names = $descs = [];
        if (! $ids || ! $conn->getSchemaBuilder()->hasTable('core_sys_lang_words')) {
            return [$names, $descs];
        }
        $keys = [];
        foreach ($ids as $id) {
            $keys[] = 'forums_forum_' . (int) $id;
            $keys[] = 'forums_forum_' . (int) $id . '_desc';
        }
        $words = $conn->table('core_sys_lang_words')->where('lang_id', 1)->where('word_app', 'forums')->whereIn('word_key', $keys)
            ->get(['word_key', 'word_default', 'word_custom']);
        foreach ($words as $w) {
            $val = ($w->word_custom !== null && $w->word_custom !== '') ? $w->word_custom : $w->word_default;
            if ($val === null || $val === '') {
                continue;
            }
            if (preg_match('/^forums_forum_(\d+)_desc$/', $w->word_key, $m)) {
                $descs[(int) $m[1]] ??= $val;
            } elseif (preg_match('/^forums_forum_(\d+)$/', $w->word_key, $m)) {
                $names[(int) $m[1]] ??= $val;
            }
        }

        return [$names, $descs];
    }

    /** Convert IPS post HTML into clean HTML (mentions→text, ipsQuote→blockquote, emoticons→alt), sanitised. */
    public static function ipsHtml(?string $html): string
    {
        $html = trim((string) $html);
        if ($html === '') {
            return '';
        }
        $html = Src::sanitizeHtml($html);

        $dom = new \DOMDocument;
        libxml_use_internal_errors(true);
        $ok = $dom->loadHTML(
            '<?xml encoding="UTF-8"><div id="ips-root">' . $html . '</div>',
            LIBXML_NONET | LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD
        );
        libxml_clear_errors();
        if (! $ok) {
            return $html;
        }
        $root = $dom->getElementById('ips-root');
        if (! $root) {
            return $html;
        }

        // Mentions → plain text.
        foreach (iterator_to_array($dom->getElementsByTagName('a')) as $a) {
            if ($a->hasAttribute('data-mentionid') || str_contains($a->getAttribute('class'), 'ipsMention')) {
                $a->parentNode?->replaceChild($dom->createTextNode($a->textContent), $a);
            }
        }

        // Emoticon images → their alt text.
        foreach (iterator_to_array($dom->getElementsByTagName('img')) as $img) {
            if ($img->hasAttribute('data-emoticon') || str_contains($img->getAttribute('class'), 'ipsEmoji')) {
                $img->parentNode?->replaceChild($dom->createTextNode($img->getAttribute('alt')), $img);
            } elseif (! $img->getAttribute('src') && $img->getAttribute('data-src')) {
                $img->setAttribute('src', $img->getAttribute('data-src'));
            }
        }

        // Quotes → clean blockquote with attribution.
        foreach (iterator_to_array($dom->getElementsByTagName('blockquote')) as $bq) {
            if (! str_contains($bq->getAttribute('class'), 'ipsQuote') && ! $bq->hasAttribute('data-ipsquote')) {
                continue;
            }
            $user = trim($bq->getAttribute('data-ipsquote-username'));
            $contents = null;
            foreach (iterator_to_array($bq->childNodes) as $child) {
                if ($child instanceof \DOMElement && str_contains($child->getAttribute('class'), 'ipsQuote_citation')) {
                    $bq->removeChild($child);

                    continue;
                }
                if ($child instanceof \DOMElement && str_contains($child->getAttribute('class'), 'ipsQuote_contents')) {
                    $contents = $child;
                }
            }
            if ($contents) {
                while ($contents->firstChild) {
                    $bq->insertBefore($contents->firstChild, $contents);
                }
                $bq->removeChild($contents);
            }
            foreach (iterator_to_array($bq->attributes) as $attr) {
                $bq->removeAttribute($attr->nodeName);
            }
            if ($user !== '') {
                $cite = $dom->createElement('p');
                $cite->appendChild($dom->createElement('strong', $user . ' wrote:'));
                $bq->insertBefore($cite, $bq->firstChild);
            }
        }

        // Strip IPS styling hooks from every element (keep href/src/alt/title).
        foreach (iterator_to_array($dom->getElementsByTagName('*')) as $el) {
            foreach (iterator_to_array($el->attributes) as $attr) {
                $name = $attr->nodeName;
                if ($name === 'class' || $name === 'style' || str_starts_with($name, 'data-')) {
                    $el->removeAttribute($name);
                }
            }
        }

        $out = '';
        foreach (iterator_to_array($root->childNodes) as $child) {
            $out .= $dom->saveHTML($child);
        }

        return trim($out);
    }
}
