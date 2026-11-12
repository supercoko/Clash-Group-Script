function main(config) {
  const ai = "🤖 AI组";
  const social = "🌐 社媒组";
  const download = "🎮 下载组";
  const foreign = "🌍 外网组";
  const domestic = "🇨🇳 国内组";
  const names = [ai, social, download, foreign, domestic];
  const nodes = (config.proxies || []).map(node => node.name);
  const nodeNames = new Set(nodes);
  const hasProviders = Object.keys(config["proxy-providers"] || {}).length > 0;
  const builtIn = new Set([
    "DIRECT", "REJECT", "REJECT-DROP", "PASS", "PASS-RULE", "COMPATIBLE", "GLOBAL"
  ]);
  const lan = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4",
    "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"];
  const subRules = config["sub-rules"] || {};
  const providers = config["rule-providers"] || {};
  const has = (object, key) => Object.prototype.hasOwnProperty.call(object, key);

  const groups = names.map(name => {
    if (nodeNames.has(name)) throw new Error(`策略组与节点重名：${name}`);
    const group = { name, type: "select", "include-all": true };
    if (name === download || name === domestic) {
      group.proxies = ["DIRECT"];
      group["default-selected"] = "DIRECT";
    } else if (nodes.length) {
      group.proxies = [nodes[0], "DIRECT"];
      group["default-selected"] = nodes[0];
    } else if (!hasProviders) {
      group.proxies = ["DIRECT"];
    }
    return group;
  });

  const preferred = [];
  function suffix(target, domains) {
    for (const domain of domains.trim().split(/\s+/)) {
      preferred.push(`DOMAIN-SUFFIX,${domain},${target}`);
    }
  }

  // Grok 的独立主机优先于 X，YouTube 的 API 和 CDN 优先于 Google。
  suffix(ai, `grok.x.com`);
  suffix(social, `youtube.com youtu.be youtube-nocookie.com youtubekids.com
    youtubeeducation.com googlevideo.com ytimg.com youtubei.googleapis.com
    youtube.googleapis.com youtube-ui.l.google.com yt3.ggpht.com
    yt3.googleusercontent.com instagram.com cdninstagram.com ig.me x.com
    twitter.com t.co twimg.com facebook.com facebook.net fb.com fbcdn.net
    fbsbx.com messenger.com m.me`);
  suffix(ai, `openai.com chatgpt.com oaistatic.com oaiusercontent.com sora.com
    claude.ai claude.com anthropic.com anthropicusercontent.com claudeusercontent.com
    grok.com x.ai google.com googleapis.com gstatic.com googleusercontent.com
    ai.google.dev deepmind.google perplexity.ai pplx.ai deepseek.com openrouter.ai
    huggingface.co hf.co midjourney.com cursor.com cursor.sh githubcopilot.com
    copilot.microsoft.com codeium.com windsurf.com runwayml.com elevenlabs.io replicate.com`);
  preferred.push(`DOMAIN-REGEX,(^|\\.)google\\.([a-z]{2}|(com|co)\\.[a-z]{2})$,${ai}`);
  suffix(download, `steamcontent.com steamcdn-a.akamaihd.net
    epicgames-download1.akamaized.net download.epicgames.com download2.epicgames.com
    download3.epicgames.com download4.epicgames.com fastly-download.epicgames.com`);

  const lastField = /^(AND|OR|NOT|SUB-RULE|DOMAIN-REGEX|PROCESS-NAME-REGEX|PROCESS-PATH-REGEX)$/;
  function migrate(rule, location, topLevel) {
    if (typeof rule !== "string") throw new Error(`${location} 应为字符串`);
    const parts = rule.split(",");
    const kind = parts[0].trim().toUpperCase();
    const index = kind === "MATCH" ? 1 : lastField.test(kind) ? parts.length - 1 : 2;
    const target = (parts[index] || "").trim();
    if (!target || (kind !== "MATCH" && index < 2)) {
      throw new Error(`${location} 缺少规则目标`);
    }
    const payload = parts.slice(1, index).join(",").trim();
    if (kind === "RULE-SET" && !has(providers, payload)) {
      throw new Error(`${location} 引用未定义的规则集：${payload}`);
    }
    if (/^(AND|OR|NOT|SUB-RULE)$/.test(kind)) {
      for (const match of payload.matchAll(/\(\s*RULE-SET\s*,\s*([^,)]+)/gi)) {
        if (!has(providers, match[1].trim())) {
          throw new Error(`${location} 引用未定义的规则集：${match[1].trim()}`);
        }
      }
    }
    if (kind === "SUB-RULE") {
      if (!has(subRules, target)) throw new Error(`${location} 引用未定义的子规则：${target}`);
      return rule;
    }
    if (topLevel && kind === "MATCH") return null;
    const sourceIp = parts.slice(index + 1).some(p => p.trim() === "src");
    const isDomestic =
      (/^(GEOSITE|GEOIP)$/.test(kind) && /^(cn|private)$/i.test(payload) && !sourceIp) ||
      (/^DOMAIN(-SUFFIX)?$/.test(kind) && /(^|\.)(cn|lan|local|localhost)$/i.test(payload)) ||
      (/^IP-CIDR6?$/.test(kind) && lan.includes(payload) && !sourceIp);
    let replacement = target;
    if (target === "DIRECT" && isDomestic) {
      replacement = domestic;
    } else if (!builtIn.has(target) && !nodeNames.has(target) && !names.includes(target)) {
      if (/广告|拦截|reject|adblock/i.test(target)) replacement = "REJECT";
      else if (/steam\s*下载|epic\s*下载|下载|download/i.test(target)) replacement = download;
      else if (/chatgpt|openai|claude|gemini|grok|\bai\b|^google$/i.test(target)) replacement = ai;
      else if (/社媒|youtube|instagram|facebook|twitter|messenger/i.test(target)) replacement = social;
      else if (isDomestic || /国内|直连|中国大陆|direct|^cn$/i.test(target)) replacement = domestic;
      else replacement = foreign;
    }
    if (replacement === target) return rule;
    parts[index] = replacement;
    return parts.join(",");
  }

  const prepend = new Set(preferred);
  const retained = (config.rules || [])
    .map((rule, i) => migrate(rule, `rules[${i}]`, true))
    .filter(rule => rule !== null && !prepend.delete(rule));
  const migratedSubRules = Object.fromEntries(Object.entries(subRules).map(([name, rules]) => [
    name, rules.map((rule, i) => migrate(rule, `sub-rules.${name}[${i}]`, false))
  ]));
  const domesticFallback = [
    `GEOSITE,private,${domestic}`, `GEOSITE,CN,${domestic}`,
    ...lan.map(cidr => `IP-CIDR${cidr.includes(":") ? "6" : ""},${cidr},${domestic},no-resolve`),
    `GEOIP,CN,${domestic}`
  ];

  config["proxy-groups"] = groups;
  if (config["sub-rules"]) config["sub-rules"] = migratedSubRules;
  const existing = new Set(retained);
  config.rules = [...preferred, ...retained,
    ...domesticFallback.filter(rule => !existing.has(rule)), `MATCH,${foreign}`];
  return config;
}
