"use strict";

// Start-up: load server info, build the form, restore the last case.
(async function boot() {
  const { $ } = RT;
  try {
    const info = await RT.api("/api/info");
    $("ver").textContent = "v" + info.version + " · " + info.social_sites + " social sites";
    RT.buildForm(info);
  } catch (e) {
    $("conn").className = "led bad";
    RT.showFormError("Could not reach the server: " + e.message);
  }
  RT.bindForm();
  RT.refreshHistory();
  setInterval(RT.refreshHistory, 4000);
  const last = sessionStorage.getItem("rectool_last");
  if (last) RT.openScan(last);
})();
