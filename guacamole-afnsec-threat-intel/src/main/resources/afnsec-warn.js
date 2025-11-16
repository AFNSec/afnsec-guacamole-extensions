/* AFNSec Password Reputation Warning — Enterprise Stable Flow (v2.3)
 *
 * - Stable Guacamole flow (token → /api/session/data/{ds}/self)
 * - Strictly per-session UI: reads attributes injected by DelegatingAuthProvider
 * - Uncacheable GET: cache-buster + no-cache headers
 * - No console logs in production; enable by setting window.__AFNSEC_DEBUG = true
 *
 * Optional runtime overrides (define before this file loads):
 *   window.__AFN_API_BASE          = '/api/'                     // default: '/api/'
 *   window.__AFNSEC_CHANGE_PWD_URL = '/#/settings'               // default: '' (hides action)
 *   window.__AFNSEC_DEBUG          = true                        // default: false
 */

(function () {
  'use strict';

  if (window.__AFNSEC_WARN_STABLE__) return;
  window.__AFNSEC_WARN_STABLE__ = true;

  var API_BASE = (window.__AFN_API_BASE || '/api/').replace(/\/?$/, '/');
  var CHANGE_PASSWORD_HREF = window.__AFNSEC_CHANGE_PWD_URL || '';
  var DEBUG_MODE = !!window.__AFNSEC_DEBUG;

  var ENTERPRISE_MESSAGE =
    "Password risk identified. This account’s password matches entries observed in threat-intelligence datasets. To protect access, update your password and avoid reusing passwords across services.";

  var TOKEN_TIMEOUT_MS = 15000;
  var API_PROBE_TIMEOUT_MS = 6000;

  function dbg(){ if (DEBUG_MODE && console && console.warn) console.warn.apply(console, arguments); }

  function injector(){ try { return angular.element(document).injector(); } catch(e){ return null; } }
  function svc(name){ var i = injector(); if (!i) return null; try { return i.get(name); } catch(e){ return null; } }

  function getTokenNow(){
    var auth = svc('authenticationService');
    return (auth && typeof auth.getCurrentToken === 'function') ? auth.getCurrentToken() : null;
  }

  function waitForToken(timeoutMs){
    var start = Date.now();
    return new Promise(function(resolve, reject){
      (function poll(){
        var t = getTokenNow();
        if (t) return resolve(t);
        if (Date.now() - start > timeoutMs) return reject(new Error('timeout: token not available'));
        setTimeout(poll, 120);
      })();
    });
  }

  // GET /api/... with token + cache-buster + no-cache headers
  function httpGetWithToken(relPath, token){
    var $http = svc('$http');
    if (!$http) return Promise.reject(new Error('$http unavailable'));
    var url = API_BASE + String(relPath).replace(/^\/+/, '');
    var sep = url.indexOf('?') === -1 ? '?' : '&';

    // Use token + sid (if available) + Date.now() to defeat caches across users
    var auth = svc('authenticationService');
    var sid = (auth && typeof auth.getCurrentToken === 'function') ? auth.getCurrentToken() : '';
    url = url + sep + 'token=' + encodeURIComponent(token) + '&sid=' + encodeURIComponent(sid) + '&_=' + Date.now();

    return $http.get(url, {
      cache: false,
      headers: {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
      }
    });
  }

  // Datasource discovery; falls back to common set
  function getDataSourcesFromApp(){
    var dss = svc('dataSourceService');
    if (dss && typeof dss.getDataSources === 'function') {
      try { var arr = dss.getDataSources(); if (Array.isArray(arr) && arr.length) return arr.slice(); } catch(e){}
    }
    var auth = svc('authenticationService');
    if (auth && typeof auth.getAvailableDataSources === 'function') {
      try { var ds = auth.getAvailableDataSources(); if (Array.isArray(ds) && ds.length) return ds.slice(); } catch(e){}
    }
    return ['mysql','ldap','quickconnect','mysql-shared','postgresql','sqlserver'];
  }

  // Probe /self on each datasource and return first attributes found
  function fetchAnySelf(token, datasources, timeoutMs){
    var start = Date.now();
    var $q = svc('$q');

    function one(ds){
      return httpGetWithToken('session/data/' + encodeURIComponent(ds) + '/self', token)
        .then(function(r){ return r && r.data && r.data.attributes ? r.data.attributes : null; })
        .catch(function(){ return null; });
    }

    var calls = datasources.map(one);
    var all = ($q ? $q.all(calls) : Promise.all(calls));
    return Promise.race([
      all.then(function(list){
        for (var i=0;i<list.length;i++) if (list[i]) return list[i];
        return null;
      }),
      new Promise(function(_, reject){
        setTimeout(function(){
          reject(new Error('timeout: /self probe exceeded '+timeoutMs+'ms'));
        }, Math.max(1000, timeoutMs - (Date.now() - start)));
      })
    ]);
  }

  // Top enterprise banner (fallback if Guac notification service is unavailable)
  function showTopBanner(message, severity){
    severity = (String(severity || 'warning')).toLowerCase();
    var notify = svc('notificationService') || svc('guacNotificationService');

    // Prefer native Guacamole notification UI if present
    if (notify && typeof notify.showStatus === 'function') {
      var actions = CHANGE_PASSWORD_HREF
        ? [{ name:'Change password now', className:'primary', callback:function(){ location.href = CHANGE_PASSWORD_HREF; } }]
        : [{ name:'Dismiss', className:'primary', callback:function(){} }];
      notify.showStatus({
        title: (severity === 'critical' ? 'Credential exposure detected' : 'Password risk identified'),
        text: message,
        className: (severity === 'critical') ? 'error' : (severity === 'warning') ? 'warning' : 'info',
        actions: actions
      });
      return;
    }

    if (document.getElementById('afnsec-top-banner')) return;

    var banner = document.createElement('div');
    banner.id = 'afnsec-top-banner';
    banner.setAttribute('role','alert');
    banner.setAttribute('aria-live','polite');
    banner.className = 'afnsec-top ' + (severity === 'critical' ? 'sev-critical' : 'sev-warning');

    var svg = '<svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path fill="currentColor" d="M12 2l7 3v6c0 5-3.4 9.4-7 11-3.6-1.6-7-6-7-11V5l7-3zm-1 12.6l6.2-6.2-1.4-1.4L11 11.8 8.2 9l-1.4 1.4L11 14.6z"/></svg>';

    banner.innerHTML =
      '<div class="afnsec-top__inner">' +
        '<div class="afnsec-top__icon">' + svg + '</div>' +
        '<div class="afnsec-top__content">' +
          '<div class="afnsec-top__title">' + (severity === 'critical' ? 'Credential exposure detected' : 'Password risk identified') + '</div>' +
          '<div class="afnsec-top__text">' + message + '</div>' +
        '</div>' +
        (CHANGE_PASSWORD_HREF ? '<a class="afnsec-top__action" href="'+ CHANGE_PASSWORD_HREF +'">Change password now</a>' : '') +
        '<button type="button" class="afnsec-top__close" aria-label="Dismiss">✕</button>' +
      '</div>';

    document.body.appendChild(banner);
    var closeBtn = banner.querySelector('.afnsec-top__close');
    if (closeBtn) closeBtn.onclick = function(){ banner.remove(); };

    // Auto-dismiss after 20s (adjust if you want persistent)
    setTimeout(function(){ try{ banner.remove(); }catch(e){} }, 20000);
  }

  // Orchestration
  var fired = false;
  function runOnce(){
    if (fired) return;
    fired = true;

    waitForToken(TOKEN_TIMEOUT_MS)
      .then(function(token){
        var ds = getDataSourcesFromApp();
        if (!ds || !ds.length) return;

        return fetchAnySelf(token, ds, API_PROBE_TIMEOUT_MS).then(function(attrs){
          if (!attrs) return;

          var show = (attrs.afnsec_warn_passhash === '1');
          if (!show) return;

          var text = attrs.afnsec_warn_passhash_text || ENTERPRISE_MESSAGE;
          var sev  = attrs.afnsec_warn_passhash_severity || 'warning';
          showTopBanner(text, sev);
        });
      })
      .catch(function(){ /* silent in production */ });
  }

  (function waitAngular(){
    if (injector()) {
      try {
        var $rootScope = svc('$rootScope');
        if ($rootScope && $rootScope.$on) $rootScope.$on('$viewContentLoaded', runOnce);
      } catch(e){}
      setTimeout(runOnce, 500);
      return;
    }
    setTimeout(waitAngular, 60);
  })();

})();
