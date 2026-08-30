<?php

namespace ErnestDefoe\Importer\Notification;

use Flarum\Notification\Blueprint\BlueprintInterface;
use Illuminate\Database\ConnectionInterface;

class FilterMutedPrivateMessageRecipients
{
    public function __construct(private ConnectionInterface $db) {}

    public function __invoke(BlueprintInterface $blueprint, array $recipients): array
    {
        if ($blueprint::getType() !== 'byobuPrivateDiscussionReplied'
            || ! $this->db->getSchemaBuilder()->hasTable('importer_pm_mutes')
            || ! ($discussionId = $blueprint->getSubject()?->getKey())) {
            return $recipients;
        }

        $muted = $this->db->table('importer_pm_mutes')->where('discussion_id', $discussionId)->pluck('user_id')
            ->map(fn ($id) => (int) $id)->all();

        return $muted
            ? array_values(array_filter($recipients, fn ($user) => ! in_array((int) $user->id, $muted, true)))
            : $recipients;
    }
}
