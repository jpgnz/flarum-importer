import Extend from 'flarum/common/extenders';
import ImporterPage from './components/ImporterPage';
import RedirectsPanel from './components/RedirectsPanel';

declare const m: any;

export default [
  // The whole importer wizard lives on the extension's settings page.
  new Extend.Admin()
    .customSetting(() => m(ImporterPage), 0)
    /*
     * Under the importer, not beside it: redirects are the step AFTER a
     * migration, and the panel shows nothing at all until a run has mapped
     * something worth redirecting to.
     */
    .customSetting(() => m(RedirectsPanel), 10),
];
