<?php

namespace ErnestDefoe\Importer;

use ErnestDefoe\Importer\Importers\Ctx;
use ErnestDefoe\Importer\Importers\Dst;
use ErnestDefoe\Importer\Importers\Registry;
use ErnestDefoe\Importer\Importers\Upload;
use Flarum\Foundation\Paths;
use Illuminate\Support\Carbon;

/** Drives importer phases in bounded, transactional batches. */
class Runner
{
    public const BATCH = 200;
    public const MODE_SHARED = 'shared';
    public const MODE_CLI = 'cli';

    public static function start(string $source, array $cfg, string $executionMode = self::MODE_SHARED, ?int $baseRunId = null): array
    {
        self::assertExecutionMode($executionMode);
        $importer = Registry::get($source);
        if (! $importer) {
            throw new \RuntimeException('Unknown import source.');
        }

        $cfg = Upload::resolve($cfg);
        $isPrivateMessages = $source === 'invision' && ! empty($cfg['ips_private_messages']);
        if ($isPrivateMessages && ($executionMode !== self::MODE_CLI || $baseRunId === null)) {
            throw new \RuntimeException('IPS private messages require CLI execution and a completed public base run.');
        }
        if (! $isPrivateMessages && $baseRunId !== null) {
            throw new \RuntimeException('Base-run map inheritance is only supported for IPS private-message child runs.');
        }
        $sourceFingerprint = method_exists($importer, 'fingerprint') ? $importer::fingerprint($cfg) : null;
        $cfg['_base_run_id'] = $baseRunId;
        Dst::reset();
        $phases = $importer::phases($cfg);
        $totals = [];
        $grand = 0;
        foreach ($phases as $phase) {
            $count = (int) ($phase->count)();
            $totals[$phase->key] = $count;
            $grand += $count;
        }

        $state = [
            'phaseIndex' => 0,
            'cursor' => null,
            'totals' => $totals,
            'grandTotal' => $grand,
            'processed' => 0,
            'summary' => [],
            'phaseLabel' => $phases[0]->label ?? 'Starting...',
        ];

        $db = Dst::db();
        $id = $db->transaction(function () use ($db, $source, $cfg, $state, $executionMode, $baseRunId, $sourceFingerprint) {
            if ($baseRunId !== null) {
                $base = $db->table('importer_runs')->where('id', $baseRunId)->lockForUpdate()->first();
                if (! $base) {
                    throw new \RuntimeException('Base import run not found.');
                }
                if ($base->status !== 'done') {
                    throw new \RuntimeException('A base import run must be complete before a child run can start.');
                }
                if ($base->source !== $source || $base->base_run_id !== null) {
                    throw new \RuntimeException('The base run must be a root import from the same source platform.');
                }
                if (! $sourceFingerprint || ! $base->source_fingerprint || ! hash_equals((string) $base->source_fingerprint, $sourceFingerprint)) {
                    throw new \RuntimeException('The child run source does not match the completed public base run.');
                }
            }

            return (int) $db->table('importer_runs')->insertGetId([
                'base_run_id' => $baseRunId,
                'source' => $source,
                'execution_mode' => $executionMode,
                'source_fingerprint' => $sourceFingerprint,
                'config' => json_encode($cfg),
                'state' => json_encode($state),
                'status' => 'running',
                'created_at' => Carbon::now(),
                'updated_at' => Carbon::now(),
            ]);
        });

        if ($executionMode === self::MODE_SHARED) {
            self::dispatch($id);
        }

        return self::status($id);
    }

    /** Explicitly make a failed or interrupted run runnable again. */
    public static function resume(int $runId, string $executionMode = self::MODE_SHARED): array
    {
        self::assertExecutionMode($executionMode);
        $db = Dst::db();
        $result = $db->transaction(function () use ($db, $runId, $executionMode) {
            $run = $db->table('importer_runs')->where('id', $runId)->lockForUpdate()->first();
            if (! $run) {
                throw new \RuntimeException('Import run not found.');
            }
            self::assertRunMode($run, $executionMode);
            if ($run->status === 'done') {
                throw new \RuntimeException('A completed import run cannot be resumed.');
            }
            if (! $run->config) {
                throw new \RuntimeException('This import run no longer has the configuration required to resume.');
            }

            $db->table('importer_runs')->where('id', $runId)->update([
                'status' => 'running',
                'error' => null,
                'locked_at' => null,
                'updated_at' => Carbon::now(),
            ]);
            $run->status = 'running';
            $run->error = null;

            return self::progressFromRun($run);
        });

        if ($executionMode === self::MODE_SHARED) {
            self::dispatch($runId);
        }

        return $result;
    }

    /** Process one phase batch for the actor that owns this execution mode. */
    public static function step(int $runId, string $executionMode = self::MODE_SHARED): array
    {
        self::assertExecutionMode($executionMode);
        Dst::reset();
        $db = Dst::db();

        return $db->transaction(function () use ($db, $runId, $executionMode) {
            $run = $db->table('importer_runs')->where('id', $runId)->lockForUpdate()->first();
            if (! $run) {
                throw new \RuntimeException('Import run not found.');
            }
            self::assertRunMode($run, $executionMode);
            if ($run->status !== 'running') {
                return self::progressFromRun($run);
            }

            $db->table('importer_runs')->where('id', $runId)->update(['locked_at' => Carbon::now()]);
            $state = json_decode($run->state, true) ?: [];

            try {
                // Nested transaction creates a savepoint. The run-row lock remains
                // held if the phase fails, while every target write is rolled back.
                return $db->transaction(function () use ($db, $run, $runId, $state) {
                    $cfg = json_decode($run->config ?: '{}', true) ?: [];
                    $importer = Registry::get($run->source);
                    if (! $importer) {
                        throw new \RuntimeException('Unknown import source.');
                    }

                    $phases = $importer::phases($cfg);
                    $phaseIndex = (int) ($state['phaseIndex'] ?? 0);
                    if ($phaseIndex >= count($phases)) {
                        self::save($runId, $state, 'done', null, true);
                        $run->state = json_encode($state);
                        $run->status = 'done';
                        $run->error = null;

                        return self::progressFromRun($run);
                    }

                    $phase = $phases[$phaseIndex];
                    $ctx = new Ctx($runId, $cfg, $run->base_run_id === null ? null : (int) $run->base_run_id, $phase->key);
                    $result = ($phase->batch)($state['cursor'] ?? null, self::BATCH, $ctx);

                    foreach (($result['summary'] ?? []) as $key => $value) {
                        $state['summary'][$key] = (int) ($state['summary'][$key] ?? 0) + (int) $value;
                    }
                    $state['processed'] = (int) ($state['processed'] ?? 0) + (int) ($result['processed'] ?? 0);
                    $state['cursor'] = $result['cursor'] ?? null;
                    $state['phaseLabel'] = $phase->label;
                    if (! empty($result['done'])) {
                        $state['phaseIndex'] = $phaseIndex + 1;
                        $state['cursor'] = null;
                    }

                    $finished = $state['phaseIndex'] >= count($phases);
                    $status = $finished ? 'done' : 'running';
                    self::save($runId, $state, $status, null, $finished);
                    $run->state = json_encode($state);
                    $run->status = $status;
                    $run->error = null;

                    return self::progressFromRun($run);
                });
            } catch (\Throwable $error) {
                // The savepoint has rolled the batch back. Mark failure before
                // releasing the row lock so no waiter can advance stale state.
                $db->table('importer_runs')->where('id', $runId)->update([
                    'status' => 'failed',
                    'error' => $error->getMessage(),
                    'locked_at' => null,
                    'updated_at' => Carbon::now(),
                ]);
                $run->status = 'failed';
                $run->error = $error->getMessage();

                return self::progressFromRun($run);
            }
        });
    }

    public static function status(int $runId): array
    {
        $run = Dst::db()->table('importer_runs')->where('id', $runId)->first();
        if (! $run) {
            return ['runId' => null, 'running' => false, 'percent' => 0, 'status' => null, 'summary' => []];
        }

        return self::progressFromRun($run);
    }

    public static function latest(): ?array
    {
        $run = Dst::db()->table('importer_runs')->orderByDesc('id')->first();

        return $run ? self::progressFromRun($run) : null;
    }

    public static function reset(int $runId, ?string $executionMode = null): void
    {
        if ($executionMode !== null) {
            self::assertExecutionMode($executionMode);
        }
        $db = Dst::db();
        [$cfg, $orphanAssets] = $db->transaction(function () use ($db, $runId, $executionMode) {
            $run = $db->table('importer_runs')->where('id', $runId)->lockForUpdate()->first();
            if (! $run) {
                return [null, []];
            }
            if ($executionMode !== null) {
                self::assertRunMode($run, $executionMode);
            }
            if ($db->table('importer_runs')->where('base_run_id', $runId)->exists()) {
                throw new \RuntimeException('This import run is the base of a child run and cannot be reset.');
            }

            // Explicit deletes also cover SQLite installations where adding a
            // foreign key to the existing map table is not supported.
            $orphanAssets = $db->table('importer_assets')->where('run_id', $runId)->where('adapter', 'local')->where('state', '<>', 'linked')->pluck('final_path')->all();
            $db->table('importer_assets')->where('run_id', $runId)->delete();
            $db->table('importer_diagnostics')->where('run_id', $runId)->delete();
            $db->table('importer_map')->where('run_id', $runId)->delete();
            $db->table('importer_runs')->where('id', $runId)->delete();

            return [$run->config ? (json_decode($run->config, true) ?: []) : [], $orphanAssets];
        });

        if ($cfg !== null) {
            self::discardOrphanAssets($orphanAssets);
            Upload::discard($cfg);
        }
    }

    private static function save(int $runId, array $state, string $status, ?string $error = null, bool $wipeConfig = false): void
    {
        $update = [
            'state' => json_encode($state),
            'status' => $status,
            'error' => $error,
            'locked_at' => null,
            'updated_at' => Carbon::now(),
        ];
        if ($wipeConfig) {
            $update['config'] = null;
        }
        Dst::db()->table('importer_runs')->where('id', $runId)->update($update);
    }

    private static function progressFromRun(object $run): array
    {
        $state = json_decode($run->state, true) ?: [];
        $status = (string) $run->status;
        $error = $run->error ?? null;
        $grand = max(1, (int) ($state['grandTotal'] ?? 1));
        $percent = $status === 'done'
            ? 100
            : (int) round(min(99, ($state['processed'] ?? 0) / $grand * 100));
        $summary = $state['summary'] ?? [];
        $executionMode = (string) ($run->execution_mode ?? self::MODE_SHARED);
        $diagnostics = [];
        if (Dst::hasTable('importer_diagnostics')) {
            foreach (Dst::db()->table('importer_diagnostics')->where('run_id', $run->id)->groupBy('severity')->selectRaw('severity, COUNT(*) aggregate')->get() as $row) {
                $diagnostics[(string) $row->severity] = (int) $row->aggregate;
            }
        }

        return [
            'runId' => (int) $run->id,
            'baseRunId' => $run->base_run_id === null ? null : (int) $run->base_run_id,
            'executionMode' => $executionMode,
            'readOnly' => $executionMode === self::MODE_CLI,
            'resumable' => $status === 'failed' && $executionMode === self::MODE_SHARED && ! empty($run->config),
            'running' => $status === 'running',
            'done' => $status === 'done',
            'failed' => $status === 'failed',
            'percent' => $percent,
            'status' => $status === 'failed'
                ? ('Import failed: ' . $error)
                : ($status === 'done' ? 'Import complete.' : ($state['phaseLabel'] ?? 'Working...')),
            'summary' => $summary,
            'diagnostics' => $diagnostics,
            'source' => null,
            'lastStatus' => $status === 'done'
                ? self::summaryLine($summary)
                : ($status === 'failed' ? ('Import failed: ' . $error) : null),
        ];
    }

    private static function assertExecutionMode(string $executionMode): void
    {
        if (! in_array($executionMode, [self::MODE_SHARED, self::MODE_CLI], true)) {
            throw new \InvalidArgumentException('Unknown importer execution mode.');
        }
    }

    private static function assertRunMode(object $run, string $executionMode): void
    {
        $actual = (string) ($run->execution_mode ?? self::MODE_SHARED);
        if ($actual !== $executionMode) {
            throw new \RuntimeException($actual === self::MODE_CLI
                ? 'CLI import runs are read-only outside their CLI process.'
                : 'Shared import runs cannot be driven by the CLI.');
        }
    }

    private static function dispatch(int $runId): void
    {
        try {
            $queue = resolve(\Illuminate\Contracts\Queue\Queue::class);
            if (! ($queue instanceof \Illuminate\Queue\SyncQueue)) {
                resolve(\Illuminate\Contracts\Bus\Dispatcher::class)
                    ->dispatch(new \ErnestDefoe\Importer\Job\RunImportJob($runId));
            }
        } catch (\Throwable) {
            // The browser loop is the shared-hosting fallback.
        }
    }

    private static function summaryLine(array $summary): string
    {
        if (isset($summary['pm_topics']) || isset($summary['pm_posts'])) {
            return 'Imported ' . ($summary['pm_topics'] ?? 0) . ' private conversations, ' . ($summary['pm_posts'] ?? 0)
                . ' private messages and ' . ($summary['pm_recipients'] ?? 0) . ' recipient records.';
        }

        return 'Imported ' . ($summary['topics'] ?? 0) . ' discussions, ' . ($summary['posts'] ?? 0) . ' posts, '
            . ($summary['users'] ?? 0) . ' members' . (isset($summary['categories']) ? ', ' . $summary['categories'] . ' tags' : '') . '.';
    }

    private static function discardOrphanAssets(array $paths): void
    {
        $root = resolve(Paths::class)->public . DIRECTORY_SEPARATOR . 'assets' . DIRECTORY_SEPARATOR . 'files';
        foreach ($paths as $relative) {
            $file = $root . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, ltrim((string) $relative, '/'));
            if (str_starts_with($file, $root . DIRECTORY_SEPARATOR) && is_file($file)) {
                @unlink($file);
            }
        }
    }
}
