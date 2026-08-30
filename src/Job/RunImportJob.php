<?php

namespace ErnestDefoe\Importer\Job;

use ErnestDefoe\Importer\Runner;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Queue\SerializesModels;

/**
 * Background driver — used only when a real queue worker is available. It loops
 * the same {@see Runner::step()} the browser uses, so the import keeps going even
 * if the admin closes the tab. The locked run row serializes it with browser
 * requests. With no queue (SyncQueue) this is never dispatched and the browser
 * does everything.
 */
class RunImportJob implements ShouldQueue
{
    use Queueable, SerializesModels;

    public int $timeout = 3600;

    public int $tries = 1;

    public function __construct(public int $runId) {}

    public function handle(): void
    {
        for ($i = 0; $i < 5_000_000; $i++) { // generous cap: 200 rows/step → up to 1e9 rows
            $st = Runner::step($this->runId, Runner::MODE_SHARED);
            if (! empty($st['done']) || ! empty($st['failed']) || empty($st['running'])) {
                break;
            }
        }
    }
}
