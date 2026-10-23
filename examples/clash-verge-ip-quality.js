// Merge into the user's existing Clash Verge global script. No personal rules.
// If main already exists, keep it and call addNetMonitorProbe before returning.
function addNetMonitorProbe(config) {
  const group = "NetMonitor-IP-Check";
  const listener = "netmonitor-ip-check";
  const port = 17893;
  const groups = Array.isArray(config["proxy-groups"]) ? config["proxy-groups"] : [];
  const listeners = Array.isArray(config.listeners) ? config.listeners : [];
  if (listeners.some(x => x && Number(x.port) === port && x.name !== listener)) {
    throw new Error("NetMonitor port 17893 conflicts with an existing listener");
  }
  const names = (Array.isArray(config.proxies) ? config.proxies : [])
    .map(x => x && x.name)
    .filter(x => typeof x === "string" && x !== "REJECT" && x !== group);
  config["proxy-groups"] = groups.filter(x => x && x.name !== group).concat([{
    name: group, type: "select", hidden: true,
    proxies: ["REJECT"].concat(Array.from(new Set(names))),
    use: Object.keys(config["proxy-providers"] || {})
  }]);
  config.listeners = listeners.filter(x => x && x.name !== listener).concat([{
    name: listener, type: "mixed", listen: "127.0.0.1", port: port,
    proxy: group, udp: false
  }]);
  return config;
}

// Only use this main when there is no existing global main function.
function main(config, profileName) {
  return addNetMonitorProbe(config);
}
