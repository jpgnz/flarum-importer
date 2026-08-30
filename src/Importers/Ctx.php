<?php

namespace ErnestDefoe\Importer\Importers;

use Illuminate\Support\Carbon;

/**
 * Per-step context handed to a phase's batch closure: the source connection and
 * the source→Flarum id maps (persisted in `importer_map` so they survive across
 * the many short requests an import runs over). Writes go through {@see Dst}.
 */
class Ctx
{
    private $src = null;

    public function __construct(
        public int $runId,
        public array $cfg,
        public ?int $baseRunId = null,
        public string $phase = 'unknown',
    ) {}

    /** The source database connection (cached for this request). */
    public function src()
    {
        return $this->src ??= Src::connect($this->cfg);
    }

    /** Record source→target id mappings without changing an established mapping. */
    public function mapPut(string $kind, array $srcToTarget): void
    {
        if (! $srcToTarget) {
            return;
        }

        $wanted = [];
        foreach ($srcToTarget as $srcId => $targetId) {
            $wanted[(string) $srcId] = (int) $targetId;
        }

        foreach (array_chunk(array_keys($wanted), 500) as $sourceIds) {
            $existing = Dst::db()->table('importer_map')
                ->where('run_id', $this->runId)
                ->where('kind', $kind)
                ->whereIn('source_id', $sourceIds)
                ->get(['source_id', 'target_id']);
            $seen = [];
            foreach ($existing as $row) {
                $sourceId = (string) $row->source_id;
                $targetId = (int) $row->target_id;
                if ($targetId !== $wanted[$sourceId]) {
                    throw new \RuntimeException(sprintf(
                        'Conflicting importer map for run %d, kind %s, source %s: existing target %d, requested target %d.',
                        $this->runId,
                        $kind,
                        $sourceId,
                        $targetId,
                        $wanted[$sourceId]
                    ));
                }
                $seen[$sourceId] = true;
            }

            $rows = [];
            foreach ($sourceIds as $sourceId) {
                if (! isset($seen[$sourceId])) {
                    $rows[] = [
                        'run_id' => $this->runId,
                        'kind' => $kind,
                        'source_id' => $sourceId,
                        'target_id' => $wanted[$sourceId],
                    ];
                }
            }
            if ($rows) {
                Dst::db()->table('importer_map')->insertOrIgnore($rows);
            }

            // A concurrent writer may have won the unique key between the read
            // and insert. Re-read to prove it wrote the same mapping.
            $stored = Dst::db()->table('importer_map')
                ->where('run_id', $this->runId)
                ->where('kind', $kind)
                ->whereIn('source_id', $sourceIds)
                ->get(['source_id', 'target_id']);
            $verified = [];
            foreach ($stored as $row) {
                $sourceId = (string) $row->source_id;
                if ((int) $row->target_id !== $wanted[$sourceId]) {
                    throw new \RuntimeException(sprintf('Conflicting importer map for run %d, kind %s, source %s.', $this->runId, $kind, $sourceId));
                }
                $verified[$sourceId] = true;
            }
            if (count($verified) !== count($sourceIds)) {
                throw new \RuntimeException(sprintf('Could not persist all importer mappings for run %d and kind %s.', $this->runId, $kind));
            }
        }
    }

    /**
     * Resolve a set of source ids to their Flarum ids for one batch.
     *
     * @return array<string,int>  source_id => target_id
     */
    public function mapGet(string $kind, array $srcIds): array
    {
        $srcIds = array_values(array_unique(array_filter(array_map('strval', $srcIds), fn ($v) => $v !== '')));
        if (! $srcIds) {
            return [];
        }
        $out = [];
        foreach (array_chunk($srcIds, 1000) as $chunk) {
            $rows = Dst::db()->table('importer_map')
                ->where('run_id', $this->runId)->where('kind', $kind)
                ->whereIn('source_id', $chunk)
                ->get(['source_id', 'target_id']);
            foreach ($rows as $r) {
                $out[(string) $r->source_id] = (int) $r->target_id;
            }
        }

        if ($this->baseRunId && count($out) < count($srcIds)) {
            $missing = array_values(array_diff($srcIds, array_keys($out)));
            foreach (array_chunk($missing, 1000) as $chunk) {
                $rows = Dst::db()->table('importer_map')
                    ->where('run_id', $this->baseRunId)->where('kind', $kind)
                    ->whereIn('source_id', $chunk)
                    ->get(['source_id', 'target_id']);
                foreach ($rows as $r) {
                    $out[(string) $r->source_id] = (int) $r->target_id;
                }
            }
        }

        return $out;
    }

    /** Store a sanitized diagnostic once, even when a batch is retried. */
    public function diagnostic(
        string $severity,
        string $code,
        string $message,
        ?string $sourceKind = null,
        string|int|null $sourceId = null,
        ?int $targetId = null,
        array $context = [],
        ?string $idempotencyKey = null,
    ): void {
        $context = self::redact($context);
        $message = self::redactMessage($message);
        $jsonFlags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE;
        $contextJson = $context ? json_encode($context, $jsonFlags) : null;
        $identity = $idempotencyKey ?? json_encode([
            $this->phase,
            $severity,
            $code,
            $sourceKind,
            $sourceId === null ? null : (string) $sourceId,
        ], $jsonFlags);

        Dst::db()->table('importer_diagnostics')->insertOrIgnore([
            'run_id' => $this->runId,
            'phase' => $this->phase,
            'severity' => $severity,
            'code' => $code,
            'source_kind' => $sourceKind,
            'source_id' => $sourceId === null ? null : (string) $sourceId,
            'target_id' => $targetId,
            'context' => $contextJson,
            'message' => $message,
            'idempotency_key' => hash('sha256', (string) $identity),
            'created_at' => Carbon::now(),
        ]);
    }

    private static function redact(array $value): array
    {
        $out = [];
        foreach ($value as $key => $item) {
            if (is_string($key) && preg_match('/pass(word)?|secret|token|credential|authorization|cookie|body|content|html|path|root|config/i', $key)) {
                $out[$key] = '[redacted]';
            } elseif (is_array($item)) {
                $out[$key] = self::redact($item);
            } elseif (is_string($item) && preg_match('~^(?:/|[A-Za-z]:[\\\\/])~', $item)) {
                $out[$key] = '[redacted]';
            } else {
                $out[$key] = $item;
            }
        }
        if (! array_is_list($out)) {
            ksort($out);
        }

        return $out;
    }

    private static function redactMessage(string $message): string
    {
        $message = preg_replace('~([a-z][a-z0-9+.-]*://[^:/\s]+:)[^@\s]+@~i', '$1[redacted]@', $message) ?? $message;
        $message = preg_replace('/\b(password|passwd|secret|token)\s*[=:]\s*\S+/i', '$1=[redacted]', $message) ?? $message;

        return preg_replace('~(?<![\w.])(?:/[\w.~-]+){2,}|[A-Za-z]:[\\\\/](?:[^\s\\\\/]+[\\\\/])+[^\s]+~', '[redacted]', $message) ?? $message;
    }
}
