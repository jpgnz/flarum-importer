<?php

namespace ErnestDefoe\Importer\Importers;

use Illuminate\Support\Carbon;
use Illuminate\Support\Str;

class AssetJournal
{
    public const RESERVED = 'reserved';
    public const FINALIZED = 'finalized';
    public const LINKED = 'linked';

    public static function reserve(
        Ctx $ctx,
        string $kind,
        string|int $sourceId,
        string $adapter,
        string $finalPath,
        ?int $expectedSize = null,
        ?string $expectedSha256 = null,
    ): object {
        $db = Dst::db();
        $sourceId = (string) $sourceId;
        $existing = self::get($ctx, $kind, $sourceId);
        if ($existing) {
            self::assertIdentity($existing, $adapter, $finalPath, $expectedSize, $expectedSha256);

            return $existing;
        }

        $now = Carbon::now();
        $db->table('importer_assets')->insertOrIgnore([
            'run_id' => $ctx->runId,
            'kind' => $kind,
            'source_id' => $sourceId,
            'uuid' => (string) Str::uuid(),
            'adapter' => $adapter,
            'final_path' => $finalPath,
            'expected_size' => $expectedSize,
            'expected_sha256' => $expectedSha256,
            'state' => self::RESERVED,
            'reserved_at' => $now,
            'created_at' => $now,
            'updated_at' => $now,
        ]);

        $stored = self::get($ctx, $kind, $sourceId);
        if (! $stored) {
            throw new \RuntimeException("Could not reserve importer asset {$kind}:{$sourceId}.");
        }
        self::assertIdentity($stored, $adapter, $finalPath, $expectedSize, $expectedSha256);

        return $stored;
    }

    public static function get(Ctx $ctx, string $kind, string|int $sourceId): ?object
    {
        return Dst::db()->table('importer_assets')
            ->where('run_id', $ctx->runId)
            ->where('kind', $kind)
            ->where('source_id', (string) $sourceId)
            ->first();
    }

    public static function markFinalized(Ctx $ctx, string $kind, string|int $sourceId, ?string $sha256 = null): void
    {
        $values = ['state' => self::FINALIZED, 'finalized_at' => Carbon::now(), 'updated_at' => Carbon::now()];
        if ($sha256 !== null) {
            $values['expected_sha256'] = $sha256;
        }
        $updated = Dst::db()->table('importer_assets')
            ->where('run_id', $ctx->runId)
            ->where('kind', $kind)
            ->where('source_id', (string) $sourceId)
            ->whereIn('state', [self::RESERVED, self::FINALIZED])
            ->update($values);
        if (! $updated) {
            $asset = self::get($ctx, $kind, $sourceId);
            if (! $asset || $asset->state !== self::LINKED) {
                throw new \RuntimeException("Could not finalize importer asset {$kind}:{$sourceId}.");
            }
        }
    }

    public static function markLinked(Ctx $ctx, string $kind, string|int $sourceId, int $targetId): void
    {
        $asset = self::get($ctx, $kind, $sourceId);
        if (! $asset || ! in_array($asset->state, [self::FINALIZED, self::LINKED], true)) {
            throw new \RuntimeException("Importer asset {$kind}:{$sourceId} is not finalized.");
        }
        if ($asset->state === self::LINKED && (int) $asset->target_id !== $targetId) {
            throw new \RuntimeException("Importer asset {$kind}:{$sourceId} is linked to another target.");
        }

        Dst::db()->table('importer_assets')->where('id', $asset->id)->update([
            'state' => self::LINKED,
            'target_id' => $targetId,
            'linked_at' => Carbon::now(),
            'updated_at' => Carbon::now(),
        ]);
    }

    private static function assertIdentity(object $asset, string $adapter, string $finalPath, ?int $size, ?string $sha256): void
    {
        if ((string) $asset->adapter !== $adapter || (string) $asset->final_path !== $finalPath) {
            throw new \RuntimeException("Conflicting importer asset identity for {$asset->kind}:{$asset->source_id}.");
        }
        if ($size !== null && $asset->expected_size !== null && (int) $asset->expected_size !== $size) {
            throw new \RuntimeException("Importer asset size changed for {$asset->kind}:{$asset->source_id}.");
        }
        if ($sha256 !== null && $asset->expected_sha256 !== null && ! hash_equals((string) $asset->expected_sha256, $sha256)) {
            throw new \RuntimeException("Importer asset hash changed for {$asset->kind}:{$asset->source_id}.");
        }
    }
}
