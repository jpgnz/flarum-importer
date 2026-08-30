<?php

declare(strict_types=1);

require __DIR__.'/../src/Importers/IpsAssets.php';

use ErnestDefoe\Importer\Importers\IpsAssets;

$attachment = (object) [
    'attach_location' => 'monthly/example.jpg',
    'attach_thumb_location' => 'monthly/example_thumb.jpg',
];

[$html, $used] = IpsAssets::rewriteHtml(
    '<p>Before <a href="<fileStore.core_Attachment>/monthly/example.jpg"><img src="<fileStore.core_Attachment>/monthly/example_thumb.jpg" data-fileid="42"></a> After</p>',
    [42 => $attachment]
);

$fails = 0;
$checks = 0;
$assert = static function (bool $condition, string $message) use (&$fails, &$checks): void {
    $checks++;
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        $fails++;
    }
};

$assert($used === [42], 'data-fileid resolves the mapped attachment');
$assert(str_contains($html, IpsAssets::placeholder(42)), 'attachment node becomes a placeholder');
$assert(! str_contains($html, 'fileStore.core_Attachment'), 'resolved IPS pseudo-URLs are removed');

$preview = '[upl-image-preview uuid=test url=/file alt=test thumbnail_url=/file]';
$markdown = IpsAssets::substitute($html, [42 => $preview], $used);
$assert(str_contains($markdown, $preview), 'placeholder becomes FoF Upload markup');
$assert(! str_contains($markdown, 'IPSATTACHMENTTOKEN'), 'no placeholder remains after substitution');

[$pathHtml, $pathUsed] = IpsAssets::rewriteHtml(
    '<a href="<fileStore.core_Attachment>/monthly/example.jpg">Download</a>',
    [42 => $attachment]
);
$assert($pathUsed === [42], 'stored path resolves when data-fileid is absent');
$assert(str_contains($pathHtml, IpsAssets::placeholder(42)), 'stored-path link becomes a placeholder');

$appended = IpsAssets::substitute('Post body', [42 => $preview], []);
$assert(str_ends_with($appended, $preview), 'mapped non-inline attachments are appended');

printf("%d IPS asset checks, %d failed\n", $checks, $fails);
exit($fails === 0 ? 0 : 1);
