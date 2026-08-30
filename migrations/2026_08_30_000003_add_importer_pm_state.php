<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Schema\Builder;

return [
    'up' => function (Builder $schema) {
        $schema->create('importer_pm_mutes', function (Blueprint $table) {
            $table->unsignedInteger('discussion_id');
            $table->unsignedInteger('user_id');
            $table->timestamp('created_at')->nullable();
            $table->primary(['discussion_id', 'user_id']);
            $table->foreign('discussion_id')->references('id')->on('discussions')->cascadeOnDelete();
            $table->foreign('user_id')->references('id')->on('users')->cascadeOnDelete();
        });
    },
    'down' => function (Builder $schema) {
        $schema->dropIfExists('importer_pm_mutes');
    },
];
