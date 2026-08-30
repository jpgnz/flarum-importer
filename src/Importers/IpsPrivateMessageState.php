<?php

namespace ErnestDefoe\Importer\Importers;

class IpsPrivateMessageState
{
    public static function lastReadPostNumber(array $posts, bool $hasUnread, int $readTime): int
    {
        if (! $posts) {
            return 0;
        }

        $lastNumber = (int) end($posts)->number;
        if (! $hasUnread) {
            return $lastNumber;
        }
        if ($readTime <= 0) {
            return 0;
        }

        foreach ($posts as $post) {
            $timestamp = is_object($post->created_at) && method_exists($post->created_at, 'getTimestamp')
                ? $post->created_at->getTimestamp()
                : strtotime((string) $post->created_at . ' UTC');
            if ($timestamp !== false && $timestamp > $readTime) {
                return max(0, (int) $post->number - 1);
            }
        }

        // Preserve IPS's authoritative unread flag even when its timestamp is stale.
        return max(0, $lastNumber - 1);
    }
}
