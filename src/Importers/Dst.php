<?php

namespace ErnestDefoe\Importer\Importers;

use Flarum\Formatter\Formatter;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;
use League\HTMLToMarkdown\HtmlConverter;

/**
 * Destination writer — turns the platform-agnostic rows the importers produce
 * into Flarum records (tags, users, discussions, posts). This is the part that
 * differs from Convoro: everything writes into Flarum's schema, and post bodies
 * are HTML → Markdown → run through Flarum's formatter so they store in the
 * parsed `content` form Flarum expects (`<t>…</t>` / `<r>…</r>`).
 */
class Dst
{
    private static ?ConnectionInterface $db = null;
    private static ?Formatter $formatter = null;
    private static ?HtmlConverter $html = null;
    private static array $tables = [];
    private static array $columns = [];

    public static function reset(): void
    {
        self::$db = null;
        self::$formatter = null;
        self::$html = null;
        self::$tables = [];
        self::$columns = [];
    }

    public static function db(): ConnectionInterface
    {
        return self::$db ??= resolve(ConnectionInterface::class);
    }

    private static function formatter(): Formatter
    {
        return self::$formatter ??= resolve(Formatter::class);
    }

    private static function html(): HtmlConverter
    {
        return self::$html ??= new HtmlConverter([
            'strip_tags' => true,
            'hard_break' => true,
            'use_autolinks' => false,
            'header_style' => 'atx',
        ]);
    }

    public static function hasTags(): bool
    {
        return self::hasTable('tags');
    }

    public static function hasTable(string $table): bool
    {
        if (array_key_exists($table, self::$tables)) {
            return self::$tables[$table];
        }
        try {
            return self::$tables[$table] = self::db()->getSchemaBuilder()->hasTable($table);
        } catch (\Throwable) {
            return false;
        }
    }

    public static function hasColumn(string $table, string $col): bool
    {
        $key = $table . '.' . $col;
        if (array_key_exists($key, self::$columns)) {
            return self::$columns[$key];
        }
        try {
            return self::$columns[$key] = self::db()->getSchemaBuilder()->hasColumn($table, $col);
        } catch (\Throwable) {
            return false;
        }
    }

    /** Convert an HTML body into Flarum's stored (parsed) content form. */
    public static function content(string $html): string
    {
        $md = trim(self::html()->convert($html !== '' ? $html : ' '));

        return self::contentFromMarkdown($md, $html);
    }

    public static function markdown(string $html): string
    {
        return trim(self::html()->convert($html !== '' ? $html : ' '));
    }

    public static function contentFromMarkdown(string $markdown, string $fallbackHtml = ''): string
    {
        $md = trim($markdown);
        if ($md === '') {
            $md = '​'; // zero-width space so the post isn't empty
        }
        try {
            return self::formatter()->parse($md, null);
        } catch (\Throwable) {
            // Never let one weird post kill the run — fall back to plain text.
            return self::formatter()->parse(strip_tags($fallbackHtml) ?: '​', null);
        }
    }

    public static function parseMarkdown(string $markdown): string
    {
        $markdown = trim($markdown);

        return self::formatter()->parse($markdown !== '' ? $markdown : '​', null);
    }

    /* ── Tags (categories) ──────────────────────────────────────────────── */

    public static function tag(string $name, string $slug, ?string $desc, ?string $color, int $position): int
    {
        $db = self::db();
        if ($id = $db->table('tags')->where('slug', $slug)->value('id')) {
            return (int) $id;
        }

        return (int) $db->table('tags')->insertGetId([
            'name' => Str::limit($name, 100, ''),
            'slug' => $slug,
            'description' => $desc !== null ? Str::limit(strip_tags($desc), 700, '') : null,
            'color' => Src::color($color),
            'position' => $position,
            'is_restricted' => 0,
            'is_hidden' => 0,
            'discussion_count' => 0,
        ]);
    }

    /** Create an IPS forum tag without silently adopting a pre-existing slug. */
    public static function ipsTag(string $name, string $slug, ?string $desc, ?string $color, int $position, ?int $parentId): int
    {
        if (! self::hasTable('tags')) {
            throw new \RuntimeException('Flarum Tags is required for the IPS migration.');
        }

        $name = Str::limit($name, 100, '');
        $existing = self::db()->table('tags')->where('slug', $slug)->first(['id', 'name']);
        if ($existing) {
            throw new \RuntimeException("Target tag slug collision for {$slug}.");
        }

        $row = [
            'name' => $name,
            'slug' => $slug,
            'description' => $desc !== null ? Str::limit(strip_tags($desc), 700, '') : null,
            'color' => Src::color($color),
            'position' => $position,
            'is_restricted' => 1,
            'is_hidden' => 0,
            'discussion_count' => 0,
        ];
        if (self::hasColumn('tags', 'is_primary')) {
            $row['is_primary'] = 1;
        }
        if (self::hasColumn('tags', 'parent_id')) {
            $row['parent_id'] = $parentId;
        }

        return (int) self::db()->table('tags')->insertGetId($row);
    }

    /* ── Groups and permissions ─────────────────────────────────────────── */

    public static function group(string $singular, string $plural, ?string $color, int $position): int
    {
        if (! self::hasTable('groups')) {
            throw new \RuntimeException('Target groups table is missing.');
        }

        $singular = Str::limit($singular, 100, '');
        $plural = Str::limit($plural, 100, '');
        $row = [
            'name_singular' => $singular,
            'name_plural' => $plural,
            'color' => $color,
            'icon' => null,
            'is_hidden' => 0,
            'position' => $position,
        ];
        if (self::hasColumn('groups', 'created_at')) {
            $row['created_at'] = Carbon::now();
        }

        return (int) self::db()->table('groups')->insertGetId($row);
    }

    public static function attachGroup(int $userId, int $groupId): void
    {
        if (! self::hasTable('group_user')) {
            throw new \RuntimeException('Target group membership table is missing.');
        }

        $row = ['user_id' => $userId, 'group_id' => $groupId];
        if (self::hasColumn('group_user', 'created_at')) {
            $row['created_at'] = Carbon::now();
        }
        self::db()->table('group_user')->insertOrIgnore($row);
    }

    /** Replace only the permissions controlled by the IPS forum migration. */
    public static function replaceIpsPermissions(array $groupIds, array $tagIds, array $grants): void
    {
        if (! self::hasTable('group_permission')) {
            throw new \RuntimeException('Target group permissions table is missing.');
        }

        $controlled = ['fof-upload.upload', 'fof-upload.download'];
        foreach ($tagIds as $tagId) {
            foreach (['viewForum', 'startDiscussion', 'discussion.reply', 'discussion.rename', 'discussion.sticky', 'discussion.lock', 'discussion.editPosts', 'discussion.hide', 'discussion.hidePosts', 'discussion.tag', 'fof-upload.download'] as $permission) {
                $controlled[] = 'tag' . (int) $tagId . '.' . $permission;
            }
        }

        foreach (array_chunk(array_values(array_unique(array_map('intval', $groupIds))), 100) as $groups) {
            foreach (array_chunk($controlled, 500) as $permissions) {
                self::db()->table('group_permission')->whereIn('group_id', $groups)->whereIn('permission', $permissions)->delete();
            }
        }

        $rows = [];
        foreach ($grants as $groupId => $permissions) {
            foreach (array_unique($permissions) as $permission) {
                $row = ['group_id' => (int) $groupId, 'permission' => $permission];
                if (self::hasColumn('group_permission', 'created_at')) {
                    $row['created_at'] = Carbon::now();
                }
                $rows[] = $row;
            }
        }
        foreach (array_chunk($rows, 500) as $chunk) {
            self::db()->table('group_permission')->insertOrIgnore($chunk);
        }
    }

    public static function flushPermissionCache(): void
    {
        try {
            $class = 'Flarum\\Group\\PermissionCache';
            if (class_exists($class)) {
                $cache = resolve($class);
                if (is_object($cache) && method_exists($cache, 'flush')) {
                    $cache->flush();
                }
            }
        } catch (\Throwable) {
            // Old Flarum versions do not have the request-local permission cache.
        }
    }

    /* ── Users ──────────────────────────────────────────────────────────── */

    public static function user(string $username, string $email, ?string $passwordHash, Carbon $joinedAt): int
    {
        $db = self::db();
        $email = mb_strtolower(trim($email));
        if ($id = $db->table('users')->where('email', $email)->value('id')) {
            return (int) $id;
        }

        // Flarum usernames are unique — disambiguate on collision.
        $base = Str::limit($username, 30, '');
        $name = $base;
        $n = 1;
        while ($db->table('users')->where('username', $name)->exists()) {
            $name = Str::limit($base, 26, '') . '_' . (++$n);
        }

        return (int) $db->table('users')->insertGetId([
            'username' => $name,
            'email' => $email,
            'is_email_confirmed' => 1,
            'password' => Src::password($passwordHash),
            'joined_at' => $joinedAt,
        ]);
    }

    /** Strict IPS user creation: explicit mappings are the only permitted merge. */
    public static function ipsUser(string $username, string $email, ?string $passwordHash, Carbon $joinedAt, ?int $explicitTargetId = null): int
    {
        $db = self::db();
        $email = mb_strtolower(trim($email));

        if ($explicitTargetId !== null) {
            if (! $db->table('users')->where('id', $explicitTargetId)->exists()) {
                throw new \RuntimeException("Explicit target user {$explicitTargetId} does not exist.");
            }

            return $explicitTargetId;
        }

        if ($db->table('users')->whereRaw('LOWER(email) = ?', [$email])->exists()) {
            throw new \RuntimeException("Unapproved target email collision for {$email}.");
        }
        if ($db->table('users')->whereRaw('LOWER(username) = ?', [mb_strtolower($username)])->exists()) {
            throw new \RuntimeException("Target username collision for {$username}.");
        }

        return (int) $db->table('users')->insertGetId([
            'username' => $username,
            'email' => $email,
            'is_email_confirmed' => 1,
            'password' => Src::password($passwordHash),
            'joined_at' => $joinedAt,
        ]);
    }

    public static function uniqueIpsUsername(string $base, int $sourceId): string
    {
        $db = self::db();
        $name = Str::limit($base, 30, '');
        if (! $db->table('users')->whereRaw('LOWER(username) = ?', [mb_strtolower($name)])->exists()) {
            return $name;
        }

        $suffix = '_' . $sourceId;
        $name = Str::limit($base, max(0, 30 - strlen($suffix)), '') . $suffix;
        if ($db->table('users')->whereRaw('LOWER(username) = ?', [mb_strtolower($name)])->exists()) {
            throw new \RuntimeException("Deterministic IPS username {$name} is already in use.");
        }

        return $name;
    }

    /* ── Discussions (topics) ───────────────────────────────────────────── */

    public static function discussion(string $title, ?int $userId, Carbon $createdAt, bool $sticky = false, bool $locked = false): int
    {
        $db = self::db();
        $title = Str::limit(trim($title) ?: 'Untitled', 200, '');
        $row = [
            'title' => $title,
            'slug' => Str::slug($title) ?: 'discussion',
            'comment_count' => 0,
            'participant_count' => 0,
            'created_at' => $createdAt,
            'user_id' => $userId,
            'last_posted_at' => $createdAt,
            'last_posted_user_id' => $userId,
            'is_private' => 0,
        ];
        // Optional columns from flarum/sticky + flarum/lock — set only if present.
        if ($sticky && self::hasColumn('discussions', 'is_sticky')) {
            $row['is_sticky'] = 1;
        }
        if ($locked && self::hasColumn('discussions', 'is_locked')) {
            $row['is_locked'] = 1;
        }

        return (int) $db->table('discussions')->insertGetId($row);
    }

    public static function privateDiscussion(string $title, ?int $userId, Carbon $createdAt): int
    {
        $title = Str::limit(trim($title) ?: 'Untitled private discussion', 200, '');

        return (int) self::db()->table('discussions')->insertGetId([
            'title' => $title,
            'slug' => Str::slug($title) ?: 'private-discussion',
            'comment_count' => 0,
            'participant_count' => 0,
            'created_at' => $createdAt,
            'user_id' => $userId,
            'last_posted_at' => $createdAt,
            'last_posted_user_id' => $userId,
            'is_private' => 1,
            'is_approved' => 1,
        ]);
    }

    public static function attachTag(int $discussionId, int $tagId): void
    {
        $db = self::db();
        $exists = $db->table('discussion_tag')->where('discussion_id', $discussionId)->where('tag_id', $tagId)->exists();
        if (! $exists) {
            $row = ['discussion_id' => $discussionId, 'tag_id' => $tagId];
            if (self::hasColumn('discussion_tag', 'created_at')) {
                $row['created_at'] = Carbon::now();
            }
            $db->table('discussion_tag')->insert($row);
        }
    }

    /** Attach tags to discussions created in the current transaction. */
    public static function attachNewTags(array $relations): void
    {
        if (! $relations) {
            return;
        }

        $createdAt = self::hasColumn('discussion_tag', 'created_at') ? Carbon::now() : null;
        $rows = [];
        foreach ($relations as [$discussionId, $tagId]) {
            $row = ['discussion_id' => (int) $discussionId, 'tag_id' => (int) $tagId];
            if ($createdAt !== null) {
                $row['created_at'] = $createdAt;
            }
            $rows[$discussionId . ':' . $tagId] = $row;
        }
        foreach (array_chunk(array_values($rows), 200) as $chunk) {
            self::db()->table('discussion_tag')->insert($chunk);
        }
    }

    /* ── Posts ──────────────────────────────────────────────────────────── */

    public static function post(int $discussionId, int $number, ?int $userId, string $html, Carbon $createdAt): int
    {
        return (int) self::db()->table('posts')->insertGetId([
            'discussion_id' => $discussionId,
            'number' => $number,
            'created_at' => $createdAt,
            'user_id' => $userId,
            'type' => 'comment',
            'content' => self::content($html),
            'is_private' => 0,
        ]);
    }

    public static function parsedPost(int $discussionId, int $number, ?int $userId, string $content, Carbon $createdAt): int
    {
        return (int) self::db()->table('posts')->insertGetId([
            'discussion_id' => $discussionId,
            'number' => $number,
            'created_at' => $createdAt,
            'user_id' => $userId,
            'type' => 'comment',
            'content' => $content,
            'is_private' => 0,
        ]);
    }

    public static function privateParsedPost(int $discussionId, int $number, ?int $userId, string $content, Carbon $createdAt, ?string $ipAddress = null): int
    {
        return (int) self::db()->table('posts')->insertGetId([
            'discussion_id' => $discussionId,
            'number' => $number,
            'created_at' => $createdAt,
            'user_id' => $userId,
            'type' => 'comment',
            'content' => $content,
            'ip_address' => $ipAddress !== null ? mb_substr($ipAddress, 0, 45) : null,
            'is_private' => 0,
            'is_approved' => 1,
        ]);
    }

    /**
     * Fill in a discussion's denormalised first/last-post + count columns from
     * its posts. Computed by aggregate query so it's correct even when the
     * discussion's posts were imported across many separate batches.
     */
    public static function finalizeDiscussion(int $did): void
    {
        $db = self::db();
        $agg = $db->table('posts')->where('discussion_id', $did)->where('type', 'comment')
            ->selectRaw('COUNT(*) c, MIN(id) first_id, COUNT(DISTINCT user_id) parts')->first();
        if (! $agg || ! $agg->c) {
            return;
        }
        $last = $db->table('posts')->where('discussion_id', $did)->orderByDesc('number')->orderByDesc('id')
            ->first(['id', 'number', 'user_id', 'created_at']);
        $db->table('discussions')->where('id', $did)->update([
            'first_post_id' => $agg->first_id,
            'last_post_id' => $last->id ?? $agg->first_id,
            'last_post_number' => $last->number ?? $agg->c,
            'last_posted_at' => $last->created_at ?? null,
            'last_posted_user_id' => $last->user_id ?? null,
            'comment_count' => max(1, (int) $agg->c),
            'participant_count' => max(1, (int) $agg->parts),
        ]);
    }

    /** Recount an IPS discussion, allowing zero participants for anonymous-only history. */
    public static function finalizeIpsDiscussion(int $did): void
    {
        $db = self::db();
        $agg = $db->table('posts')->where('discussion_id', $did)->where('type', 'comment')
            ->selectRaw('COUNT(*) c, COUNT(DISTINCT user_id) parts')->first();
        if (! $agg || ! $agg->c) {
            return;
        }
        $first = $db->table('posts')->where('discussion_id', $did)->where('type', 'comment')->orderBy('number')->orderBy('id')->first(['id']);
        $last = $db->table('posts')->where('discussion_id', $did)->where('type', 'comment')->orderByDesc('number')->orderByDesc('id')
            ->first(['id', 'number', 'user_id', 'created_at']);
        $db->table('discussions')->where('id', $did)->update([
            'first_post_id' => $first->id,
            'last_post_id' => $last->id,
            'last_post_number' => $last->number,
            'last_posted_at' => $last->created_at,
            'last_posted_user_id' => $last->user_id,
            'comment_count' => (int) $agg->c,
            'participant_count' => (int) $agg->parts,
        ]);
    }

    public static function recountUsers(array $userIds): void
    {
        if (! $userIds) {
            return;
        }
        $db = self::db();
        $db->table('users')->whereIn('id', array_values(array_unique(array_map('intval', $userIds))))->update([
            'discussion_count' => $db->raw('(SELECT COUNT(*) FROM discussions WHERE discussions.user_id = users.id)'),
            'comment_count' => $db->raw("(SELECT COUNT(*) FROM posts WHERE posts.user_id = users.id AND posts.type = 'comment')"),
        ]);
    }

    public static function recountTags(array $tagIds): void
    {
        $tagIds = array_values(array_unique(array_map('intval', $tagIds)));
        if (! $tagIds || ! self::hasTable('tags')) {
            return;
        }

        $db = self::db();
        foreach ($tagIds as $tagId) {
            $last = $db->table('discussion_tag as dt')->join('discussions as d', 'd.id', '=', 'dt.discussion_id')
                ->where('dt.tag_id', $tagId)->orderByDesc('d.last_posted_at')->orderByDesc('d.id')
                ->first(['d.id', 'd.last_posted_at', 'd.last_posted_user_id']);
            $row = [
                'discussion_count' => (int) $db->table('discussion_tag')->where('tag_id', $tagId)->count(),
            ];
            if (self::hasColumn('tags', 'last_posted_at')) {
                $row['last_posted_at'] = $last->last_posted_at ?? null;
            }
            if (self::hasColumn('tags', 'last_posted_discussion_id')) {
                $row['last_posted_discussion_id'] = $last->id ?? null;
            }
            if (self::hasColumn('tags', 'last_posted_user_id')) {
                $row['last_posted_user_id'] = $last->last_posted_user_id ?? null;
            }
            $db->table('tags')->where('id', $tagId)->update($row);
        }
    }
}
