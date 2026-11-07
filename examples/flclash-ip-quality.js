// FlClash: bind this script to EACH intended profile after preserving standard/script extensions.
// NetMonitor public configuration helper. Contains no subscription or credentials.
// Existing per-profile main: merge this function and call it AFTER existing transforms.
// Do not replace a user's complete script. See docs/PROXY_SETUP.md.
function addNetMonitorProbe(config) {
  if (!config || typeof config !== "object" || Array.isArray(config)) {
    throw new Error("NetMonitor expects a configuration object");
  }
  const group = "NetMonitor-IP-Check";
  const listener = "netmonitor-ip-check";
  const port = 17893;
  for (const field of ["proxies", "proxy-groups", "listeners"]) {
    if (config[field] !== undefined && !Array.isArray(config[field])) {
      throw new Error("NetMonitor: unexpected array field " + field);
    }
  }
  const providers = config["proxy-providers"] || {};
  if (typeof providers !== "object" || Array.isArray(providers)) {
    throw new Error("NetMonitor: unexpected proxy-providers structure");
  }
  const groups = config["proxy-groups"] || [];
  const listeners = config.listeners || [];
  for (const key of ["port", "mixed-port", "socks-port", "redir-port", "tproxy-port"]) {
    if (Number(config[key]) === port) {
      throw new Error("NetMonitor port conflicts with ordinary inbound " + key);
    }
  }
  if (listeners.some(x => x && Number(x.port) === port && x.name !== listener)) {
    throw new Error("NetMonitor port 17893 conflicts with another listener");
  }
  const existingGroups = groups.filter(x => x && x.name === group);
  if (existingGroups.length > 1 || existingGroups.some(x => x.type !== "select" || x.hidden !== true)) {
    throw new Error("NetMonitor reserved group conflicts with existing configuration");
  }
  const existingListeners = listeners.filter(x => x && x.name === listener);
  if (existingListeners.length > 1 || existingListeners.some(x =>
    x.type !== "mixed" || x.listen !== "127.0.0.1" || Number(x.port) !== port ||
    x.proxy !== group || x.udp !== false ||
    (x.users !== undefined && (!Array.isArray(x.users) || x.users.length !== 0)))) {
    throw new Error("NetMonitor reserved listener conflicts with existing configuration");
  }
  const names = (config.proxies || [])
    .filter(x => x && !["direct", "reject", "pass", "compatible"].includes(String(x.type || "").toLowerCase()))
    .map(x => x.name)
    .filter(name => typeof name === "string" && name && name !== group &&
      !["DIRECT", "REJECT", "PASS", "COMPATIBLE"].includes(name.toUpperCase()));
  config["proxy-groups"] = groups.filter(x => !x || x.name !== group).concat([{
    name: group, type: "select", hidden: true,
    proxies: ["REJECT"].concat(Array.from(new Set(names))),
    use: Object.keys(providers)
  }]);
  config.listeners = listeners.filter(x => !x || x.name !== listener).concat([{
    name: listener, type: "mixed", listen: "127.0.0.1", port,
    proxy: group, udp: false, users: []
  }]);
  return config;
}

// Use this entry point ONLY when no existing per-profile main needs preservation.
function main(config) {
  return addNetMonitorProbe(config);
}
