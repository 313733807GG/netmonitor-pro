// NetMonitor: FlClash v0.9.2 profile extension script (main(config)).
// Bind explicitly to each intended profile. Keep existing custom scripts by
// merging the helper into their main; never overwrite another script wholesale.
// Script mode replaces FlClash's standard added-rule/match-target extension.
// Check those settings before changing modes. This file adds no routing rules.
function addNetMonitorProbe(config) {
  const group = "NetMonitor-IP-Check";
  const listener = "netmonitor-ip-check";
  const port = 17893;
  const groups = Array.isArray(config["proxy-groups"]) ? config["proxy-groups"] : [];
  const listeners = Array.isArray(config.listeners) ? config.listeners : [];
  if (listeners.some(x => x && Number(x.port) === port && x.name !== listener)) {
    throw new Error("NetMonitor port 17893 conflicts with an existing listener");
  }
  const existing = groups.find(x => x && x.name === group);
  if (existing && (existing.type !== "select" || existing.hidden !== true)) {
    throw new Error("NetMonitor-IP-Check is already used by another group");
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
function main(config) {
  return addNetMonitorProbe(config);
}
