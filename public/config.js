/* config.js — FIntraX PKI runtime config (preserves keys; no duplication) */
(function () {
  // Note: cache headers should be set server-side; no-op here.

  // Helpers
  function n(v, d) { var x = Number(v); return isFinite(x) ? x : d; }
  function b1(v) { return String(v || '') === '1'; }

  // Canonical config
  var cfg = {
    appName: "<%= process.env.APP_NAME || 'FIntraX' %>",
    orgName: "<%= process.env.ORG_NAME || 'Organisation' %>",

    api: {
      // Optional base URL (leave blank for same-origin)
      base: "<%= process.env.API_BASE || process.env.API_BASE_URL || '' %>",

      // Client behavior
      timeout: <%= Number(process.env.API_TIMEOUT_MS || 30000) %>,
      retryAttempts: <%= Number(process.env.API_RETRY_ATTEMPTS || 2) %>,

      // Canonical PKI endpoints (single source of truth)
      pki: {
        get: "/api/pki",
        put: "/api/pki",
        log: "/api/pki/history",
        state: "/api/pki/state",

        certificates: "/api/pki/certificates",
        generateCertificate: "/api/pki/certificates/generate",
        revokeCertificate: "/api/pki/certificates",

        // signing + verification
        signDocument: "/api/pki/documents/sign",
        verifyDocument: "/api/pki/documents/verify",

        // other functional areas
        signatures: "/api/pki/signatures",
        tsaConfig: "/api/pki/tsa/config",
        audit: "/api/pki/audit",
        dashboardStats: "/api/pki/dashboard/stats",

        // users
        users: "/api/pki/users",
        addUser: "/api/pki/users",
        deleteUser: "/api/pki/users",

        // HSM status (server-provided)
        hsmStatus: "/api/pki/hsm/status"
      },

      // PKCS#11 (SC-HSM, etc.)
      pkcs11: {
        info: "/api/pkcs11/info",
        capabilities: "/api/pkcs11/capabilities",
        mechanisms: "/api/pkcs11/mechanisms",
        objects: "/api/pkcs11/objects",
        keygen: "/api/pkcs11/keygen",
        pubkey: "/api/pkcs11/pubkey",
        status: "/api/pkcs11/sc-hsm-status",
        init: "/api/pkcs11/init",            // init via soPin/userPin
        setUserPin: "/api/pkcs11/set-user-pin",
        unblockUserPin: "/api/pkcs11/unblock-user-pin"
      },

      // External docs (optional)
      docs: "<%= process.env.DOCS_URL || '' %>"
    },

    ui: {
      primary: "<%= process.env.UI_PRIMARY || '#0ea5e9' %>",
      headerTitle: "<%= process.env.HEADER_TITLE || 'FintraX - PKI Platform' %>",
      footerText: "<% if (process.env.COPYRIGHT) { %>© <%= new Date().getFullYear() %> <%= process.env.COPYRIGHT %><% } else { %>© <%= new Date().getFullYear() %> FIntraX Congo<% } %>",
      sidebarTitle: "<%= process.env.SIDEBAR_TITLE || 'FIntraX' %>",
      logoText: "<%= process.env.LOGO_TEXT || process.env.APP_NAME || 'FIntraX Congo' %>",
      tagline: "<%= process.env.BRAND_TAGLINE || '' %>",

      // Frontend knobs (safe defaults)
      autoRefresh: <%= String(process.env.UI_AUTO_REFRESH || '') === '1' ? 'true' : 'false' %>,
      refreshInterval: <%= Number(process.env.UI_REFRESH_INTERVAL_MS || 30000) %>,
      maxFileSize: <%= Number(process.env.UI_MAX_FILE_SIZE_BYTES || 10 * 1024 * 1024) %>
    }
  };

  // Install config
  window.APP_CONFIG = cfg;

  // Back-compat: expose legacy `api.endpoints` as a direct alias (no duplication).
  // Anything that still reads APP_CONFIG.api.endpoints will see the exact same object.
  window.APP_CONFIG.api.endpoints = window.APP_CONFIG.api.pki;
})();
