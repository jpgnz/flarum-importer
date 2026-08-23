<?php

namespace ErnestDefoe\Importer\Api\Controller;

use ErnestDefoe\Importer\Importers\Dst;
use ErnestDefoe\Importer\Redirects\Patterns;
use Flarum\Http\RequestUtil;
use Flarum\Settings\SettingsRepositoryInterface;
use Illuminate\Support\Arr;
use Laminas\Diactoros\Response\JsonResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Switch redirects on for one run and one platform, or off again.
 *
 * 🚨 **This refuses rather than saves a setting that would do nothing.** Every
 * failure this can prevent is silent by nature: a run whose map was reset, a
 * platform with no patterns, a run id that no longer exists. Each one saves
 * cleanly, reports success and then sends every old address back to the same
 * 404 — and nobody finds out until the traffic that used to arrive stops. The
 * checks below are the difference between a feature and the appearance of one.
 */
class RedirectSaveController implements RequestHandlerInterface
{
    public function __construct(protected SettingsRepositoryInterface $settings)
    {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        RequestUtil::getActor($request)->assertAdmin();

        $body = (array) $request->getParsedBody();

        // Off is always allowed, and never needs a reason.
        if (! Arr::get($body, 'enabled', false)) {
            $this->settings->set('ernestdefoe-importer.redirect_run', 0);
            $this->settings->set('ernestdefoe-importer.redirect_source', '');

            return new JsonResponse(['ok' => true, 'enabled' => false]);
        }

        $runId = (int) Arr::get($body, 'runId', 0);
        $source = (string) Arr::get($body, 'source', '');

        if (! Patterns::known($source)) {
            return $this->refuse('unknown-source');
        }

        $run = $runId > 0
            ? Dst::db()->table('importer_runs')->where('id', $runId)->first()
            : null;

        if (! $run) {
            return $this->refuse('no-such-run');
        }

        /*
         * 🚨 The map has to actually hold something. It is written during the
         * run and deleted by a reset, so a run can sit there looking finished
         * with nothing left to look up — and that is exactly the state somebody
         * reaches by re-running an import, which is what people do when the
         * first attempt went wrong.
         */
        $mapped = Dst::db()->table('importer_map')->where('run_id', $runId)->count();

        if ($mapped < 1) {
            return $this->refuse('empty-map');
        }

        $this->settings->set('ernestdefoe-importer.redirect_run', $runId);
        $this->settings->set('ernestdefoe-importer.redirect_source', $source);

        return new JsonResponse([
            'ok' => true,
            'enabled' => true,
            'runId' => $runId,
            'source' => $source,
            'mapped' => $mapped,
        ]);
    }

    /**
     * 🚨 422 and a reason the UI can translate, not a 500 and not a silent
     * `ok: false`. The person is one click from believing this is on.
     */
    protected function refuse(string $reason): JsonResponse
    {
        return new JsonResponse(['ok' => false, 'reason' => $reason], 422);
    }
}
