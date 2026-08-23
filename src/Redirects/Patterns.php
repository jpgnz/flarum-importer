<?php

/*
 * This file is part of ernestdefoe/importer.
 */

namespace ErnestDefoe\Importer\Redirects;

/**
 * What the old forum's addresses looked like, per source.
 *
 * 🚨 **This table is the feature.** Everything else here is a lookup and a 301;
 * the value is in knowing that phpBB says `viewtopic.php?t=`, XenForo says
 * `/threads/slug.123/`, SMF says `index.php?topic=123.0` and Web Wiz says
 * `forum_posts.asp?TID=`. Getting one of those wrong costs somebody every
 * inbound link to that section of their forum, and nothing anywhere would say
 * so — the pages simply 404 and the search results quietly die.
 *
 * ## What a pattern is
 *
 * A regular expression over the path AND query together, with one capture
 * group: the id in the old system. `kind` says which map to look it up in —
 * `topic`, `tag` or `user`, matching what the importer wrote.
 *
 * 🚨 The SLUG in an old URL is ignored everywhere it appears. Every forum here
 * resolves by id and treats the slug as decoration, so `/threads/anything.123/`
 * and `/threads/the-real-title.123/` are the same page. Matching on the slug
 * would break every link whose title has since been edited — which is most of
 * the interesting ones.
 */
final class Patterns
{
    /**
     * 🚨 Ordered, and the order matters within a source: the most specific
     * pattern must come first. vBulletin's `/threads/123-slug` and phpBB's
     * `viewtopic.php?t=` can both appear on a vBulletin 4 site, and a loose
     * pattern placed first would swallow a URL the next one would have read
     * correctly.
     *
     * @return array<string, list<array{kind: string, pattern: string, example: string}>>
     */
    public static function all(): array
    {
        return [
            'phpbb' => [
                ['kind' => 'topic', 'pattern' => '~(?:^|/)viewtopic\.php\?(?:.*&)?t=(\d+)~i', 'example' => '/viewtopic.php?f=2&t=1234'],
                ['kind' => 'tag', 'pattern' => '~(?:^|/)viewforum\.php\?(?:.*&)?f=(\d+)~i', 'example' => '/viewforum.php?f=2'],
                ['kind' => 'user', 'pattern' => '~(?:^|/)memberlist\.php\?.*\bu=(\d+)~i', 'example' => '/memberlist.php?mode=viewprofile&u=5'],
            ],

            'xenforo' => [
                /*
                 * 🚨 The id is at the END, after a dot: `slug.123/`. XenForo
                 * also serves every one of these under `index.php?` on a site
                 * without friendly URLs, which is why the leading part is
                 * permissive rather than anchored to `/`.
                 */
                ['kind' => 'topic', 'pattern' => '~threads/(?:[^/?]*\.)?(\d+)~i', 'example' => '/threads/my-topic.123/'],
                ['kind' => 'tag', 'pattern' => '~forums/(?:[^/?]*\.)?(\d+)~i', 'example' => '/forums/general.4/'],
                ['kind' => 'user', 'pattern' => '~members/(?:[^/?]*\.)?(\d+)~i', 'example' => '/members/alice.9/'],
            ],

            'vbulletin' => [
                // vB4 friendly URLs put the id FIRST, before a dash.
                ['kind' => 'topic', 'pattern' => '~threads/(\d+)~i', 'example' => '/threads/123-my-topic'],
                ['kind' => 'tag', 'pattern' => '~forums/(\d+)~i', 'example' => '/forums/4-general'],
                // vB3, and vB4 without friendly URLs.
                ['kind' => 'topic', 'pattern' => '~showthread\.php\?(?:.*&)?t=(\d+)~i', 'example' => '/showthread.php?t=123'],
                ['kind' => 'tag', 'pattern' => '~forumdisplay\.php\?(?:.*&)?f=(\d+)~i', 'example' => '/forumdisplay.php?f=4'],
                ['kind' => 'user', 'pattern' => '~member\.php\?(?:.*&)?u=(\d+)~i', 'example' => '/member.php?u=9'],
            ],

            'vbulletin5' => [
                ['kind' => 'topic', 'pattern' => '~(?:^|/)(\d+)-[^/?]+$~', 'example' => '/123-my-topic'],
                ['kind' => 'topic', 'pattern' => '~node/(\d+)~i', 'example' => '/node/123'],
            ],

            'mybb' => [
                ['kind' => 'topic', 'pattern' => '~showthread\.php\?(?:.*&)?tid=(\d+)~i', 'example' => '/showthread.php?tid=123'],
                ['kind' => 'tag', 'pattern' => '~forumdisplay\.php\?(?:.*&)?fid=(\d+)~i', 'example' => '/forumdisplay.php?fid=4'],
                // MyBB's rewritten form.
                ['kind' => 'topic', 'pattern' => '~thread-(\d+)~i', 'example' => '/thread-123.html'],
                ['kind' => 'tag', 'pattern' => '~forum-(\d+)~i', 'example' => '/forum-4.html'],
            ],

            'smf' => [
                /*
                 * 🚨 SMF's id carries a message offset after a dot —
                 * `topic=123.60` means "topic 123, from message 60". The
                 * capture stops at the dot deliberately: the offset cannot be
                 * honoured (see Resolver) and taking it as part of the id would
                 * mean matching nothing at all.
                 */
                ['kind' => 'topic', 'pattern' => '~[?&]topic=(\d+)~i', 'example' => '/index.php?topic=123.0'],
                ['kind' => 'tag', 'pattern' => '~[?&]board=(\d+)~i', 'example' => '/index.php?board=4.0'],
            ],

            'vanilla' => [
                ['kind' => 'topic', 'pattern' => '~discussion/(\d+)~i', 'example' => '/discussion/123/my-topic'],
                ['kind' => 'tag', 'pattern' => '~categories/([^/?]+)~i', 'example' => '/categories/general'],
            ],

            'nodebb' => [
                ['kind' => 'topic', 'pattern' => '~topic/(\d+)~i', 'example' => '/topic/123/my-topic'],
                ['kind' => 'tag', 'pattern' => '~category/(\d+)~i', 'example' => '/category/4/general'],
                ['kind' => 'user', 'pattern' => '~user/([^/?]+)~i', 'example' => '/user/alice'],
            ],

            'invision' => [
                ['kind' => 'topic', 'pattern' => '~topic/(\d+)~i', 'example' => '/topic/123-my-topic/'],
                ['kind' => 'tag', 'pattern' => '~forum/(\d+)~i', 'example' => '/forum/4-general/'],
                ['kind' => 'user', 'pattern' => '~profile/(\d+)~i', 'example' => '/profile/9-alice/'],
                // IPS without friendly URLs.
                ['kind' => 'topic', 'pattern' => '~showtopic=(\d+)~i', 'example' => '/index.php?showtopic=123'],
            ],

            'discourse' => [
                /*
                 * 🚨 Discourse puts the id LAST — `/t/slug/123` — and also
                 * serves `/t/123` and `/t/123/456`, where the second number is
                 * a POST within the topic.
                 *
                 * 🚨 The bare-id pattern MUST come first, and this was wrong
                 * the first time round. With the slugged one first, `/t/123/456`
                 * matched it — reading `123` as the slug and `456` as the topic
                 * — so every link anybody ever made to a specific reply landed
                 * on a DIFFERENT DISCUSSION. Not a 404, which somebody would
                 * notice: the wrong page, served confidently.
                 *
                 * The bare pattern cannot make the same mistake in reverse,
                 * because it needs digits immediately after `/t/` and a slug
                 * never is.
                 */
                ['kind' => 'topic', 'pattern' => '~/t/(\d+)(?:/|$|\?)~i', 'example' => '/t/123'],
                ['kind' => 'topic', 'pattern' => '~/t/[^/?]+/(\d+)~i', 'example' => '/t/my-topic/123'],
                ['kind' => 'tag', 'pattern' => '~/c/([^/?]+)~i', 'example' => '/c/general'],
                ['kind' => 'user', 'pattern' => '~/u/([^/?]+)~i', 'example' => '/u/alice'],
            ],

            'convoro' => [
                ['kind' => 'topic', 'pattern' => '~topic/(\d+)~i', 'example' => '/topic/123-my-topic'],
                ['kind' => 'tag', 'pattern' => '~forum/([^/?]+)~i', 'example' => '/forum/general'],
            ],

            'webwiz' => [
                ['kind' => 'topic', 'pattern' => '~forum_posts\.asp\?(?:.*&)?TID=(\d+)~i', 'example' => '/forum_posts.asp?TID=123'],
                ['kind' => 'tag', 'pattern' => '~forum_topics\.asp\?(?:.*&)?FID=(\d+)~i', 'example' => '/forum_topics.asp?FID=4'],
            ],
        ];
    }

    /** @return list<array{kind: string, pattern: string, example: string}> */
    public static function for(string $source): array
    {
        return self::all()[$source] ?? [];
    }

    /**
     * Whether a source has any patterns at all.
     *
     * 🚨 A source with none must be able to say so rather than offer a switch
     * that does nothing. `vbulletin5` in particular is thin, because vBulletin
     * 5's addresses are configurable to the point where there is no shape worth
     * promising.
     */
    public static function known(string $source): bool
    {
        return self::for($source) !== [];
    }
}
