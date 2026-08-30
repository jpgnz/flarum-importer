<?php

namespace ErnestDefoe\Importer\Console;

use ErnestDefoe\Importer\Importers\Registry;
use ErnestDefoe\Importer\Runner;
use Flarum\Console\AbstractCommand;
use Symfony\Component\Console\Input\InputOption;

/**
 * Headless import — drives the same step engine the admin wizard uses, in a
 * loop. Handy on hosts that do have SSH (and for very large migrations run
 * inside screen/tmux). On shared hosting without SSH, use the admin panel; the
 * engine is identical.
 */
class RunImportCommand extends AbstractCommand
{
    /** Safety net so a stuck run can't spin the CLI forever. Matches RunImportJob. */
    private const MAX_STEPS = 5_000_000;

    protected function configure(): void
    {
        $this
            ->setName('importer:run')
            ->setDescription('Import a forum into Flarum from another platform.')
            ->addOption('resume', null, InputOption::VALUE_REQUIRED, 'Resume an existing CLI run ID')
            ->addOption('base-run', null, InputOption::VALUE_REQUIRED, 'Completed base run whose mappings this child may read')
            ->addOption('source', null, InputOption::VALUE_REQUIRED, 'Source platform: ' . implode(', ', array_keys(Registry::map())))
            ->addOption('driver', null, InputOption::VALUE_REQUIRED, 'DB driver (mysql|pgsql|sqlite)', 'mysql')
            ->addOption('host', null, InputOption::VALUE_REQUIRED, 'DB host', '127.0.0.1')
            ->addOption('port', null, InputOption::VALUE_REQUIRED, 'DB port', '')
            ->addOption('database', null, InputOption::VALUE_REQUIRED, 'DB name', '')
            ->addOption('username', null, InputOption::VALUE_REQUIRED, 'DB username', 'root')
            ->addOption('password', null, InputOption::VALUE_REQUIRED, 'DB password', '')
            ->addOption('prefix', null, InputOption::VALUE_REQUIRED, 'Source table prefix', '')
            ->addOption('uploads-root', null, InputOption::VALUE_REQUIRED, 'IPS uploads directory (required for IPS files)', '')
            ->addOption('user-mappings', null, InputOption::VALUE_REQUIRED, 'JSON object mapping IPS member IDs to existing Flarum user IDs', '')
            ->addOption('reactions', null, InputOption::VALUE_NONE, 'Import enabled IPS reactions')
            ->addOption('polls', null, InputOption::VALUE_NONE, 'Import recoverable IPS polls')
            ->addOption('profiles', null, InputOption::VALUE_NONE, 'Import selected IPS profile fields')
            ->addOption('signatures', null, InputOption::VALUE_NONE, 'Import IPS signatures')
            ->addOption('private-messages', null, InputOption::VALUE_NONE, 'Import IPS private messages as a child of a completed public run')
            ->addOption('test', null, InputOption::VALUE_NONE, 'Only test the connection + show counts.');
    }

    protected function fire(): int
    {
        try {
            $resumeId = (int) $this->input->getOption('resume');
            if ($resumeId) {
                if ($this->input->getOption('test') || $this->input->getOption('base-run') || $this->input->getOption('source')) {
                    throw new \InvalidArgumentException('--resume cannot be combined with --source, --test or --base-run.');
                }
                $start = Runner::resume($resumeId, Runner::MODE_CLI);
            } else {
                $source = (string) $this->input->getOption('source');
                $importer = Registry::get($source);
                if (! $importer) {
                    throw new \InvalidArgumentException('Unknown source "' . $source . '". Available: ' . implode(', ', array_keys(Registry::map())));
                }
                $cfg = [
                    'driver' => (string) $this->input->getOption('driver'),
                    'host' => (string) $this->input->getOption('host'),
                    'port' => (string) $this->input->getOption('port'),
                    'database' => (string) $this->input->getOption('database'),
                    'username' => (string) $this->input->getOption('username'),
                    'password' => (string) $this->input->getOption('password'),
                    'prefix' => (string) $this->input->getOption('prefix'),
                    'uploads_root' => (string) $this->input->getOption('uploads-root'),
                    'ips_user_mappings' => (string) $this->input->getOption('user-mappings'),
                    'ips_reactions' => (bool) $this->input->getOption('reactions'),
                    'ips_polls' => (bool) $this->input->getOption('polls'),
                    'ips_profiles' => (bool) $this->input->getOption('profiles'),
                    'ips_signatures' => (bool) $this->input->getOption('signatures'),
                ];

                if ($this->input->getOption('test')) {
                    $r = $importer::test($cfg);
                    $this->info('Connection OK - ' . json_encode($r['counts'] ?? []));

                    return 0;
                }

                $baseRunId = (int) $this->input->getOption('base-run') ?: null;
                if ($this->input->getOption('private-messages')) {
                    if ($source !== 'invision' || $baseRunId === null) {
                        throw new \InvalidArgumentException('--private-messages requires --source=invision and --base-run=<completed-public-run-id>.');
                    }
                    if ($this->input->getOption('reactions') || $this->input->getOption('polls') || $this->input->getOption('profiles') || $this->input->getOption('signatures')) {
                        throw new \InvalidArgumentException('--private-messages cannot be combined with public optional phases.');
                    }
                    $cfg['ips_private_messages'] = true;
                }
                $start = Runner::start($source, $cfg, Runner::MODE_CLI, $baseRunId);
            }

            $runId = (int) $start['runId'];
            $this->info(sprintf('[%s] Import run ID: %d', date('Y-m-d H:i:s'), $runId));
            $lastPercent = -1;
            $lastStatus = null;
            $lastOutputAt = 0;
            // Same generous cap the queued job uses (200 rows/step → up to 1e9
            // rows), so a state machine that never reaches done/failed can't spin
            // this process forever.
            for ($i = 0; $i < self::MAX_STEPS; $i++) {
                $st = Runner::step($runId, Runner::MODE_CLI);
                $now = time();
                $status = (string) ($st['status'] ?? 'Working...');
                if ($st['percent'] !== $lastPercent || $status !== $lastStatus || $now - $lastOutputAt >= 60) {
                    $this->info(sprintf('[%s] [%3d%%] run %d: %s', date('Y-m-d H:i:s'), $st['percent'], $runId, $status));
                    $lastPercent = $st['percent'];
                    $lastStatus = $status;
                    $lastOutputAt = $now;
                }
                if (! empty($st['failed'])) {
                    $this->error($st['status']);
                    $this->error('Resume with: php flarum importer:run --resume=' . $runId);

                    return 1;
                }
                if (! empty($st['done'])) {
                    $this->info('Import complete - ' . ($st['lastStatus'] ?? ''));

                    return 0;
                }
            }

            $this->error(sprintf(
                'Import gave up after %s steps without finishing - run %d may be stuck. Resume it with importer:run --resume=%d.',
                number_format(self::MAX_STEPS),
                $runId,
                $runId
            ));

            return 1;
        } catch (\Throwable $e) {
            $this->error('Import failed: ' . $e->getMessage());

            return 1;
        }
    }
}
