<?php

namespace ErnestDefoe\Importer\Importers;

use Flarum\Foundation\Paths;
use Flarum\Http\UrlGenerator;
use Illuminate\Support\Carbon;

class IpsAssetUnavailable extends \RuntimeException {}

class IpsAssets
{
    public const ADAPTER = 'local';

    public static function validateConfig(array $cfg): string
    {
        $root = rtrim((string) ($cfg['uploads_root'] ?? ''), DIRECTORY_SEPARATOR);
        if ($root === '' || ! is_dir($root) || ! is_readable($root)) {
            throw new \RuntimeException('IPS preflight failed: --uploads-root must be a readable directory.');
        }

        $sourceRoot = realpath($root);
        if ($sourceRoot === false) {
            throw new \RuntimeException('IPS preflight failed: uploads root could not be resolved.');
        }

        $target = self::targetRoot();
        if ((! is_dir($target) && ! @mkdir($target, 0775, true)) || ! is_writable($target)) {
            throw new \RuntimeException('IPS preflight failed: FoF Upload local storage is not writable.');
        }

        return $sourceRoot;
    }

    public static function reserveAttachment(Ctx $ctx, object $attachment): object
    {
        [$source, $size, $extension] = self::inspectAttachment($ctx->cfg, $attachment);
        $token = hash('sha256', $ctx->runId . "\0" . (string) ($attachment->attach_security_key ?? '') . "\0" . (string) $attachment->attach_location);
        $path = 'importer/' . $ctx->runId . '/' . substr($token, 0, 2) . '/' . $token . '.' . $extension;

        return AssetJournal::reserve($ctx, 'attachment', $attachment->attach_id, self::ADAPTER, $path, (int) $size);
    }

    public static function inspectAttachment(array $cfg, object $attachment): array
    {
        $source = self::sourcePath($cfg, (string) $attachment->attach_location);
        $size = filesize($source);
        if ($size === false) {
            throw new IpsAssetUnavailable("Could not read IPS attachment {$attachment->attach_id} size.");
        }
        if ($size > 64 * 1024 * 1024) {
            throw new IpsAssetUnavailable("IPS attachment {$attachment->attach_id} exceeds the 64 MiB processing limit.");
        }
        $mime = (new \finfo(FILEINFO_MIME_TYPE))->file($source) ?: 'application/octet-stream';

        return [$source, (int) $size, self::safeExtension($mime)];
    }

    public static function finalizeAttachment(Ctx $ctx, object $attachment): object
    {
        $asset = self::reserveAttachment($ctx, $attachment);
        $source = self::sourcePath($ctx->cfg, (string) $attachment->attach_location);
        $target = self::targetPath((string) $asset->final_path);
        $temp = $target . '.part';

        if (self::matches($target, (int) $asset->expected_size)) {
            $sourceHash = hash_file('sha256', $source);
            $targetHash = hash_file('sha256', $target);
            if (! is_string($sourceHash) || ! is_string($targetHash) || ! hash_equals($sourceHash, $targetHash)) {
                @unlink($target);
                throw new \RuntimeException("Existing IPS attachment {$attachment->attach_id} failed hash verification.");
            }
            AssetJournal::markFinalized($ctx, 'attachment', $attachment->attach_id, $sourceHash);

            return AssetJournal::get($ctx, 'attachment', $attachment->attach_id);
        }

        $parent = dirname($target);
        if ((! is_dir($parent) && ! @mkdir($parent, 0775, true)) || ! is_writable($parent)) {
            throw new \RuntimeException("Cannot create target directory for IPS attachment {$attachment->attach_id}.");
        }

        $input = @fopen($source, 'rb');
        $output = @fopen($temp, 'wb');
        if (! is_resource($input) || ! is_resource($output)) {
            if (is_resource($input)) {
                fclose($input);
            }
            if (is_resource($output)) {
                fclose($output);
            }
            @unlink($temp);
            throw new \RuntimeException("Could not stream IPS attachment {$attachment->attach_id}.");
        }

        $sourceHash = hash_init('sha256');
        try {
            while (! feof($input)) {
                $chunk = fread($input, 1024 * 1024);
                if ($chunk === false) {
                    throw new \RuntimeException("Could not read IPS attachment {$attachment->attach_id}.");
                }
                if ($chunk === '') {
                    continue;
                }
                hash_update($sourceHash, $chunk);
                $offset = 0;
                $length = strlen($chunk);
                while ($offset < $length) {
                    $written = fwrite($output, substr($chunk, $offset));
                    if ($written === false || $written === 0) {
                        throw new \RuntimeException("Could not copy IPS attachment {$attachment->attach_id}.");
                    }
                    $offset += $written;
                }
            }
            if (! fflush($output)) {
                throw new \RuntimeException("Could not flush IPS attachment {$attachment->attach_id}.");
            }
        } finally {
            fclose($input);
            fclose($output);
        }

        if (! self::matches($temp, (int) $asset->expected_size)) {
            @unlink($temp);
            throw new \RuntimeException("Copied IPS attachment {$attachment->attach_id} failed size verification.");
        }
        if (! @rename($temp, $target)) {
            @unlink($temp);
            throw new \RuntimeException("Could not finalize IPS attachment {$attachment->attach_id}.");
        }

        AssetJournal::markFinalized($ctx, 'attachment', $attachment->attach_id, hash_final($sourceHash));

        return AssetJournal::get($ctx, 'attachment', $attachment->attach_id);
    }

    public static function linkAttachment(Ctx $ctx, object $attachment, object $asset, bool $hidden = false): array
    {
        if (! Dst::hasTable('fof_upload_files') || ! Dst::hasTable('fof_upload_file_posts')) {
            throw new \RuntimeException('FoF Upload tables are required for IPS attachments.');
        }
        if ((string) $asset->state === AssetJournal::LINKED) {
            $row = Dst::db()->table('fof_upload_files')->where('id', $asset->target_id)->first();
            if (! $row) {
                throw new \RuntimeException("Linked IPS attachment {$attachment->attach_id} has no FoF file row.");
            }

            return [$row, self::preview($row)];
        }

        $target = self::targetPath((string) $asset->final_path);
        if (! self::matches($target, (int) $asset->expected_size)) {
            throw new \RuntimeException("IPS attachment {$attachment->attach_id} is not finalized.");
        }
        if (! $asset->expected_sha256 || ! hash_equals((string) $asset->expected_sha256, (string) hash_file('sha256', $target))) {
            throw new \RuntimeException("IPS attachment {$attachment->attach_id} failed final hash verification.");
        }
        $mime = (new \finfo(FILEINFO_MIME_TYPE))->file($target) ?: 'application/octet-stream';
        $isImage = str_starts_with($mime, 'image/');
        $width = $height = null;
        if ($isImage && ($dimensions = @getimagesize($target))) {
            $width = (int) $dimensions[0];
            $height = (int) $dimensions[1];
        }
        $tag = $isImage ? 'image-preview' : 'file';
        $url = self::targetUrl((string) $asset->final_path);
        $now = Carbon::createFromTimestamp(max(1, (int) ($attachment->attach_date ?? time())));
        $actorMap = $ctx->mapGet('user', [(int) ($attachment->attach_member_id ?? 0)]);
        $fileId = (int) Dst::db()->table('fof_upload_files')->insertGetId([
            'actor_id' => $actorMap[(string) (int) ($attachment->attach_member_id ?? 0)] ?? null,
            'base_name' => self::safeBaseName((string) ($attachment->attach_file ?: basename((string) $asset->final_path))),
            'path' => (string) $asset->final_path,
            'url' => $url,
            'type' => $mime,
            'size' => (int) $asset->expected_size,
            'upload_method' => self::ADAPTER,
            'created_at' => $now,
            'remote_id' => null,
            'uuid' => (string) $asset->uuid,
            'tag' => $tag,
            'hidden' => $hidden ? 1 : 0,
            'shared' => 0,
            'image_width' => $width,
            'image_height' => $height,
            'thumbnail_url' => null,
            'thumbnail_path' => null,
            'thumbnail_width' => null,
            'thumbnail_height' => null,
        ]);
        $ctx->mapPut('attachment', [(int) $attachment->attach_id => $fileId]);
        AssetJournal::markLinked($ctx, 'attachment', $attachment->attach_id, $fileId);
        $row = Dst::db()->table('fof_upload_files')->where('id', $fileId)->first();

        return [$row, self::preview($row)];
    }

    public static function attachToPost(int $fileId, int $postId): void
    {
        if (! Dst::db()->table('fof_upload_file_posts')->where('file_id', $fileId)->where('post_id', $postId)->exists()) {
            Dst::db()->table('fof_upload_file_posts')->insert(['file_id' => $fileId, 'post_id' => $postId]);
        }
    }

    public static function existingAttachment(Ctx $ctx, object $attachment, int $fileId): array
    {
        $sourceId = (int) $attachment->attach_id;
        if (! $ctx->baseRunId) {
            throw new \RuntimeException('Reusing an attachment requires a base run.');
        }
        $asset = Dst::db()->table('importer_assets')->where('run_id', $ctx->baseRunId)
            ->where('kind', 'attachment')->where('source_id', (string) $sourceId)->first();
        if (! $asset || $asset->state !== AssetJournal::LINKED || (int) $asset->target_id !== $fileId) {
            throw new \RuntimeException("Base attachment {$sourceId} is not durably linked to FoF file {$fileId}.");
        }
        $target = self::targetPath((string) $asset->final_path);
        if (! self::matches($target, (int) $asset->expected_size)
            || ! $asset->expected_sha256
            || ! hash_equals((string) $asset->expected_sha256, (string) hash_file('sha256', $target))) {
            throw new \RuntimeException("Base attachment {$sourceId} failed file verification.");
        }
        $source = self::sourcePath($ctx->cfg, (string) $attachment->attach_location);
        if (filesize($source) !== (int) $asset->expected_size
            || ! hash_equals((string) $asset->expected_sha256, (string) hash_file('sha256', $source))) {
            throw new \RuntimeException("Current source attachment {$sourceId} does not match the public base run.");
        }
        $row = Dst::db()->table('fof_upload_files')->where('id', $fileId)->first();
        if (! $row) {
            throw new \RuntimeException("Mapped FoF Upload file {$fileId} does not exist.");
        }

        return [$row, self::preview($row)];
    }

    public static function placeholder(int $attachmentId): string
    {
        return 'IPSATTACHMENTTOKEN' . $attachmentId . 'ENDTOKEN';
    }

    public static function rewriteHtml(string $html, array $attachments): array
    {
        if ($html === '' || ! $attachments) {
            return [$html, []];
        }
        $dom = new \DOMDocument;
        libxml_use_internal_errors(true);
        $ok = $dom->loadHTML('<?xml encoding="UTF-8"><div id="ips-asset-root">' . $html . '</div>', LIBXML_NONET | LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);
        libxml_clear_errors();
        if (! $ok || ! ($root = $dom->getElementById('ips-asset-root'))) {
            return [$html, []];
        }

        $used = [];
        foreach (iterator_to_array($dom->getElementsByTagName('*')) as $element) {
            if (! $element instanceof \DOMElement || ! $element->hasAttribute('data-fileid')) {
                continue;
            }
            $id = (int) $element->getAttribute('data-fileid');
            if (! isset($attachments[$id])) {
                continue;
            }
            $replace = $element;
            if ($element->parentNode instanceof \DOMElement && strtolower($element->parentNode->tagName) === 'a') {
                $replace = $element->parentNode;
            }
            $replace->parentNode?->replaceChild($dom->createTextNode(self::placeholder($id)), $replace);
            $used[$id] = true;
        }

        foreach ($attachments as $id => $attachment) {
            if (isset($used[$id])) {
                continue;
            }
            $paths = array_filter([(string) $attachment->attach_location, (string) ($attachment->attach_thumb_location ?? '')]);
            foreach (iterator_to_array($dom->getElementsByTagName('a')) as $anchor) {
                $href = $anchor->getAttribute('href');
                if (self::containsStoredPath($href, $paths)) {
                    $anchor->parentNode?->replaceChild($dom->createTextNode(self::placeholder((int) $id)), $anchor);
                    $used[(int) $id] = true;
                    break;
                }
            }
            if (isset($used[$id])) {
                continue;
            }
            foreach (iterator_to_array($dom->getElementsByTagName('img')) as $image) {
                if (self::containsStoredPath($image->getAttribute('src'), $paths)) {
                    $image->parentNode?->replaceChild($dom->createTextNode(self::placeholder((int) $id)), $image);
                    $used[(int) $id] = true;
                    break;
                }
            }
        }

        $out = '';
        foreach (iterator_to_array($root->childNodes) as $child) {
            $out .= $dom->saveHTML($child);
        }

        return [$out, array_keys($used)];
    }

    public static function substitute(string $markdown, array $previews, array $used): string
    {
        foreach ($previews as $id => $preview) {
            $markdown = str_replace(self::placeholder((int) $id), $preview, $markdown);
        }
        foreach ($previews as $id => $preview) {
            if (! in_array((int) $id, array_map('intval', $used), true)) {
                $markdown .= "\n\n" . $preview;
            }
        }

        return trim($markdown);
    }

    private static function preview(object $file): string
    {
        $fileClass = 'FoF\\Upload\\File';
        $utilClass = 'FoF\\Upload\\Helpers\\Util';
        if (! class_exists($fileClass) || ! class_exists($utilClass)) {
            throw new \RuntimeException('FoF Upload formatter integration is unavailable.');
        }
        $model = new $fileClass;
        $model->setRawAttributes((array) $file, true);
        $preview = resolve($utilClass)->getBbcodeForFile($model);
        if (! is_string($preview) || $preview === '') {
            throw new \RuntimeException("FoF Upload template {$file->tag} could not render imported file {$file->id}.");
        }

        return $preview;
    }

    private static function containsStoredPath(string $value, array $paths): bool
    {
        foreach ($paths as $path) {
            if ($path !== '' && str_contains(rawurldecode($value), $path)) {
                return true;
            }
        }

        return false;
    }

    private static function safeBaseName(string $name): string
    {
        $name = preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $name) ?? '';
        $name = str_replace(['[', ']', '"', "'", '<', '>'], '', $name);
        $name = preg_replace('/\s+/u', ' ', trim($name)) ?? '';

        return mb_substr($name !== '' ? $name : 'attachment', 0, 255);
    }

    public static function sourcePath(array $cfg, string $relative): string
    {
        $root = self::validateConfig($cfg);
        $candidate = realpath($root . DIRECTORY_SEPARATOR . ltrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $relative), DIRECTORY_SEPARATOR));
        if ($candidate === false || ! is_file($candidate) || ! is_readable($candidate) || ($candidate !== $root && ! str_starts_with($candidate, $root . DIRECTORY_SEPARATOR))) {
            throw new IpsAssetUnavailable('IPS attachment file is missing, unreadable, or outside uploads root.');
        }

        return $candidate;
    }

    private static function targetRoot(): string
    {
        return resolve(Paths::class)->public . DIRECTORY_SEPARATOR . 'assets' . DIRECTORY_SEPARATOR . 'files';
    }

    private static function targetPath(string $relative): string
    {
        $root = self::targetRoot();
        $path = $root . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, ltrim($relative, '/'));
        if (! str_starts_with($path, $root . DIRECTORY_SEPARATOR)) {
            throw new \RuntimeException('Invalid importer asset target path.');
        }

        return $path;
    }

    private static function targetUrl(string $relative): string
    {
        return resolve(UrlGenerator::class)->to('forum')->path('assets/files/' . ltrim(str_replace('\\', '/', $relative), '/'));
    }

    private static function matches(string $path, int $size): bool
    {
        return is_file($path) && is_readable($path) && filesize($path) === $size;
    }

    private static function safeExtension(string $mime): string
    {
        return match (strtolower($mime)) {
            'image/jpeg' => 'jpg',
            'image/png' => 'png',
            'image/gif' => 'gif',
            'image/webp' => 'webp',
            'image/avif' => 'avif',
            'application/pdf' => 'pdf',
            'application/zip' => 'zip',
            'application/x-rar', 'application/vnd.rar' => 'rar',
            'application/x-7z-compressed' => '7z',
            'text/plain' => 'txt',
            'text/csv' => 'csv',
            'application/msword' => 'doc',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => 'docx',
            'application/vnd.ms-excel' => 'xls',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' => 'xlsx',
            'application/vnd.ms-powerpoint' => 'ppt',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation' => 'pptx',
            'audio/mpeg' => 'mp3',
            'video/mp4' => 'mp4',
            'application/octet-stream' => 'bin',
            'image/svg+xml', 'text/html', 'application/xhtml+xml', 'application/x-httpd-php', 'text/x-php' => throw new IpsAssetUnavailable("Unsupported active attachment MIME type {$mime}."),
            default => 'bin',
        };
    }
}
