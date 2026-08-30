<?php

declare(strict_types=1);

require __DIR__.'/../src/Importers/IpsPrivateMessageState.php';

use ErnestDefoe\Importer\Importers\IpsPrivateMessageState;

$posts = [
    (object) ['number' => 1, 'created_at' => '2026-01-01 00:00:00'],
    (object) ['number' => 2, 'created_at' => '2026-01-02 00:00:00'],
    (object) ['number' => 3, 'created_at' => '2026-01-03 00:00:00'],
];

$checks = [
    [false, 0, 3, 'fully read overrides an absent timestamp'],
    [false, strtotime('2026-01-01 00:00:00 UTC'), 3, 'fully read uses the final post number'],
    [true, 0, 0, 'unread with no timestamp is never read'],
    [true, strtotime('2026-01-01 00:00:00 UTC'), 1, 'messages strictly after the cutoff are unread'],
    [true, strtotime('2026-01-02 00:00:00 UTC'), 2, 'a message at the cutoff remains read'],
    [true, strtotime('2027-01-01 00:00:00 UTC'), 2, 'stale timestamps preserve the authoritative unread flag'],
];

$fails = 0;
foreach ($checks as [$unread, $time, $expected, $message]) {
    $actual = IpsPrivateMessageState::lastReadPostNumber($posts, $unread, $time);
    if ($actual !== $expected) {
        fwrite(STDERR, "FAIL: {$message}; expected {$expected}, got {$actual}\n");
        $fails++;
    }
}

printf("%d IPS PM state checks, %d failed\n", count($checks), $fails);
exit($fails === 0 ? 0 : 1);
