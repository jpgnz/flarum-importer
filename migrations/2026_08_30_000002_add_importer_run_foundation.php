<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Schema\Builder;

return [
    'up' => function (Builder $schema) {
        $db = $schema->getConnection();
        $supportsAlterForeignKeys = $db->getDriverName() !== 'sqlite';

        // Check every duplicate before changing data, so a conflict never leaves
        // the schema partially upgraded or the map partially deduplicated.
        $duplicates = $db->table('importer_map')
            ->select(['run_id', 'kind', 'source_id'])
            ->groupBy(['run_id', 'kind', 'source_id'])
            ->havingRaw('COUNT(*) > 1')
            ->get();
        $identical = [];
        foreach ($duplicates as $duplicate) {
            $rows = $db->table('importer_map')
                ->where('run_id', $duplicate->run_id)
                ->where('kind', $duplicate->kind)
                ->where('source_id', $duplicate->source_id)
                ->orderBy('id')
                ->get(['id', 'target_id']);
            $targets = [];
            foreach ($rows as $row) {
                $targets[(string) $row->target_id] = true;
            }
            if (count($targets) !== 1) {
                throw new RuntimeException(sprintf(
                    'Conflicting importer map for run %d, kind %s, source %s.',
                    $duplicate->run_id,
                    $duplicate->kind,
                    $duplicate->source_id
                ));
            }
            $identical[] = $rows;
        }
        foreach ($identical as $rows) {
            $ids = [];
            foreach ($rows as $index => $row) {
                if ($index > 0) {
                    $ids[] = $row->id;
                }
            }
            if ($ids) {
                $db->table('importer_map')->whereIn('id', $ids)->delete();
            }
        }

        $schema->table('importer_runs', function (Blueprint $table) {
            $table->unsignedInteger('base_run_id')->nullable()->after('id');
            $table->string('execution_mode', 20)->default('shared')->after('source');
            $table->string('source_fingerprint', 64)->nullable()->after('execution_mode');
            $table->index('base_run_id', 'importer_runs_base_run');
            $table->index('execution_mode', 'importer_runs_execution_mode');
        });

        $schema->table('importer_map', function (Blueprint $table) use ($supportsAlterForeignKeys) {
            $table->unique(['run_id', 'kind', 'source_id'], 'importer_map_run_kind_source_unique');
            if ($supportsAlterForeignKeys) {
                $table->foreign('run_id', 'importer_map_run_foreign')
                    ->references('id')->on('importer_runs')->cascadeOnDelete();
            }
        });

        if ($supportsAlterForeignKeys) {
            $schema->table('importer_runs', function (Blueprint $table) {
                $table->foreign('base_run_id', 'importer_runs_base_run_foreign')
                    ->references('id')->on('importer_runs')->restrictOnDelete();
            });
        }

        $schema->create('importer_diagnostics', function (Blueprint $table) {
            $table->increments('id');
            $table->unsignedInteger('run_id');
            $table->string('phase', 80);
            $table->string('severity', 20);
            $table->string('code', 100);
            $table->string('source_kind', 40)->nullable();
            $table->string('source_id', 64)->nullable();
            $table->unsignedInteger('target_id')->nullable();
            $table->mediumText('context')->nullable();
            $table->text('message');
            $table->string('idempotency_key', 64);
            $table->timestamp('created_at')->nullable();
            $table->unique(['run_id', 'idempotency_key'], 'importer_diagnostics_run_key_unique');
            $table->index(['run_id', 'phase', 'severity'], 'importer_diagnostics_run_phase_severity');
            $table->foreign('run_id')->references('id')->on('importer_runs')->cascadeOnDelete();
        });

        $schema->create('importer_assets', function (Blueprint $table) {
            $table->increments('id');
            $table->unsignedInteger('run_id');
            $table->string('kind', 40);
            $table->string('source_id', 64);
            $table->string('uuid', 64);
            $table->string('adapter', 100);
            $table->string('final_path', 512);
            $table->unsignedBigInteger('expected_size')->nullable();
            $table->string('expected_sha256', 64)->nullable();
            $table->string('state', 20)->default('reserved');
            $table->unsignedInteger('target_id')->nullable();
            $table->timestamp('reserved_at')->nullable();
            $table->timestamp('finalized_at')->nullable();
            $table->timestamp('linked_at')->nullable();
            $table->timestamp('created_at')->nullable();
            $table->timestamp('updated_at')->nullable();
            $table->unique(['run_id', 'kind', 'source_id'], 'importer_assets_run_kind_source_unique');
            $table->index(['run_id', 'state'], 'importer_assets_run_state');
            $table->foreign('run_id')->references('id')->on('importer_runs')->cascadeOnDelete();
        });
    },
    'down' => function (Builder $schema) {
        $supportsAlterForeignKeys = $schema->getConnection()->getDriverName() !== 'sqlite';

        $schema->dropIfExists('importer_assets');
        $schema->dropIfExists('importer_diagnostics');

        $schema->table('importer_map', function (Blueprint $table) use ($supportsAlterForeignKeys) {
            if ($supportsAlterForeignKeys) {
                $table->dropForeign('importer_map_run_foreign');
            }
            $table->dropUnique('importer_map_run_kind_source_unique');
        });
        $schema->table('importer_runs', function (Blueprint $table) use ($supportsAlterForeignKeys) {
            if ($supportsAlterForeignKeys) {
                $table->dropForeign('importer_runs_base_run_foreign');
            }
            $table->dropIndex('importer_runs_base_run');
            $table->dropIndex('importer_runs_execution_mode');
            $table->dropColumn(['base_run_id', 'execution_mode', 'source_fingerprint']);
        });
    },
];
