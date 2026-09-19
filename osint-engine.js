// Darknode OSINT Engine — email/domain/IP intelligence, Google dorking,
// social media reconnaissance, metadata extraction, geolocation tools.
// Pure browser JS, ES module. No external dependencies.

// ═══════════════════════════════════════════════════════════════════════════════
// §1  EMAIL OSINT
// ═══════════════════════════════════════════════════════════════════════════════

export function guessEmailFormats(firstName, lastName, domain) {
  const f = firstName.toLowerCase().trim();
  const l = lastName.toLowerCase().trim();
  const fi = f[0] || "";
  const li = l[0] || "";
  return [
    `${f}.${l}@${domain}`, `${f}${l}@${domain}`, `${fi}${l}@${domain}`,
    `${f}_${l}@${domain}`, `${f}-${l}@${domain}`, `${fi}.${l}@${domain}`,
    `${f}${li}@${domain}`, `${l}.${f}@${domain}`, `${l}${f}@${domain}`,
    `${l}${fi}@${domain}`, `${f}@${domain}`, `${l}@${domain}`,
    `${fi}${li}@${domain}`, `${f}.${li}@${domain}`, `${li}${f}@${domain}`,
  ];
}

export function parseEmailHeaders(raw) {
  const lines = raw.replace(/\r\n\s+/g, " ").split(/\r?\n/);
  const headers = [];
  for (const line of lines) {
    const m = line.match(/^([A-Za-z0-9-]+):\s*(.*)$/);
    if (m) headers.push({ name: m[1], value: m[2] });
  }

  const result = {
    from: "", to: "", subject: "", date: "",
    receivedChain: [], messageId: "",
    spf: null, dkim: null, dmarc: null,
    originatingIP: null, returnPath: "",
    xMailer: "", contentType: "",
  };

  for (const h of headers) {
    const n = h.name.toLowerCase();
    if (n === "from") result.from = h.value;
    else if (n === "to") result.to = h.value;
    else if (n === "subject") result.subject = h.value;
    else if (n === "date") result.date = h.value;
    else if (n === "message-id") result.messageId = h.value;
    else if (n === "return-path") result.returnPath = h.value;
    else if (n === "x-mailer") result.xMailer = h.value;
    else if (n === "content-type") result.contentType = h.value;
    else if (n === "received") {
      result.receivedChain.push(h.value);
      const ipMatch = h.value.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);
      if (ipMatch && !result.originatingIP) {
        const ip = ipMatch[1];
        if (!ip.startsWith("10.") && !ip.startsWith("192.168.") && !ip.startsWith("127."))
          result.originatingIP = ip;
      }
    }
    else if (n === "authentication-results") {
      const spfMatch = h.value.match(/spf=(\w+)/i);
      const dkimMatch = h.value.match(/dkim=(\w+)/i);
      const dmarcMatch = h.value.match(/dmarc=(\w+)/i);
      if (spfMatch) result.spf = spfMatch[1];
      if (dkimMatch) result.dkim = dkimMatch[1];
      if (dmarcMatch) result.dmarc = dmarcMatch[1];
    }
    else if (n === "received-spf") {
      const m2 = h.value.match(/^(\w+)/);
      if (m2 && !result.spf) result.spf = m2[1];
    }
  }

  result.receivedChain.reverse();
  return result;
}

// ═══════════════════════════════════════════════════════════════════════════════
// §2  DOMAIN OSINT
// ═══════════════════════════════════════════════════════════════════════════════

export function parseWhoisFields(raw) {
  const fields = {};
  for (const line of raw.split(/\r?\n/)) {
    const m = line.match(/^\s*([^:]+):\s*(.+)$/);
    if (m) {
      const key = m[1].trim().toLowerCase().replace(/\s+/g, "_");
      fields[key] = (fields[key] ? fields[key] + "; " : "") + m[2].trim();
    }
  }
  return {
    domainName: fields.domain_name || fields["domain name"] || "",
    registrar: fields.registrar || "",
    creationDate: fields.creation_date || fields.created || fields["registration date"] || "",
    expirationDate: fields.expiration_date || fields["registry expiry date"] || fields.expires || "",
    updatedDate: fields.updated_date || fields["last updated"] || "",
    nameServers: (fields.name_server || fields.nserver || "").split(/;\s*/),
    status: (fields.domain_status || fields.status || "").split(/;\s*/),
    registrantOrg: fields.registrant_organization || fields["registrant org"] || "",
    registrantCountry: fields.registrant_country || "",
    dnssec: fields.dnssec || "",
  };
}

export function analyzeDNSRecords(records) {
  const analysis = { findings: [], riskScore: 0 };
  const types = records.map(r => r.type);

  if (!types.includes("MX")) {
    analysis.findings.push({ severity: "info", finding: "No MX records — domain does not receive email" });
  }

  const spfRecords = records.filter(r => r.type === "TXT" && r.value.startsWith("v=spf1"));
  if (spfRecords.length === 0) {
    analysis.findings.push({ severity: "high", finding: "No SPF record — domain is vulnerable to email spoofing" });
    analysis.riskScore += 30;
  } else if (spfRecords.length > 1) {
    analysis.findings.push({ severity: "medium", finding: "Multiple SPF records — only one should exist (RFC 7208)" });
    analysis.riskScore += 10;
  } else {
    const spf = spfRecords[0].value;
    if (spf.includes("+all")) {
      analysis.findings.push({ severity: "critical", finding: "SPF uses +all — allows anyone to send as this domain" });
      analysis.riskScore += 50;
    } else if (spf.includes("~all")) {
      analysis.findings.push({ severity: "low", finding: "SPF uses ~all (soft fail) — consider -all for strict enforcement" });
    }
  }

  const dmarcRecords = records.filter(r => r.type === "TXT" && r.name.startsWith("_dmarc") && r.value.startsWith("v=DMARC1"));
  if (dmarcRecords.length === 0) {
    analysis.findings.push({ severity: "high", finding: "No DMARC record — email authentication not enforced" });
    analysis.riskScore += 25;
  } else {
    const dmarc = dmarcRecords[0].value;
    if (dmarc.includes("p=none")) {
      analysis.findings.push({ severity: "medium", finding: "DMARC policy is 'none' — only monitoring, not enforcing" });
      analysis.riskScore += 10;
    }
  }

  if (!types.includes("CAA")) {
    analysis.findings.push({ severity: "low", finding: "No CAA records — any CA can issue certificates for this domain" });
  }

  if (!types.includes("AAAA")) {
    analysis.findings.push({ severity: "info", finding: "No AAAA records — domain not IPv6 accessible" });
  }

  return analysis;
}

export function domainAge(creationDate) {
  const created = new Date(creationDate);
  if (isNaN(created.getTime())) return null;
  const now = new Date();
  const years = (now - created) / (365.25 * 86400000);
  return {
    years: Math.floor(years),
    days: Math.floor((now - created) / 86400000),
    created: created.toISOString().slice(0, 10),
    isNew: years < 0.25,
    isYoung: years < 1,
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// §3  SUBDOMAIN WORDLIST
// ═══════════════════════════════════════════════════════════════════════════════

export const SUBDOMAIN_WORDLIST = [
  "www","mail","remote","blog","webmail","server","ns1","ns2","smtp","secure",
  "vpn","m","shop","ftp","mail2","test","portal","ns","ww1","host","support",
  "dev","web","bbs","ww42","mx","email","cloud","1","mail1","2","forum","owa",
  "www2","gw","admin","store","mx1","cdn","api","exchange","app","gov","2tty",
  "vps","govyty","hmail","mmail","noc","new","www1","smp","news","cpanel",
  "webdisk","record","img","cpcalendars","cpcontacts","autodiscover","whm",
  "autoconfig","db","mssql","demo","cp","pma","cms","adm","mx2","login",
  "gateway","dns","dns1","dns2","intranet","extranet","staging","stage",
  "preprod","pre-prod","production","prod","internal","external","public",
  "private","beta","alpha","delta","gamma","omega","testing","qa","uat",
  "sandbox","develop","development","int","integration","ci","cd","jenkins",
  "gitlab","github","bitbucket","jira","confluence","wiki","docs","doc",
  "documentation","help","helpdesk","ticket","tickets","service","services",
  "monitor","monitoring","status","health","metrics","grafana","prometheus",
  "kibana","elastic","elasticsearch","logstash","splunk","siem","log","logs",
  "audit","backup","backups","bak","archive","storage","s3","cdn1","cdn2",
  "static","assets","media","images","img1","img2","video","files","download",
  "downloads","upload","uploads","share","repo","repository","registry",
  "docker","k8s","kubernetes","rancher","nomad","consul","vault","terraform",
  "ansible","puppet","chef","salt","config","configuration","settings",
  "panel","dashboard","control","manager","manage","management","console",
  "admin2","administrator","root","sysadmin","devops","ops","infra",
  "infrastructure","network","net","lan","wan","dmz","firewall","fw","proxy",
  "reverse","lb","loadbalancer","haproxy","nginx","apache","iis","tomcat",
  "node","nodejs","python","php","ruby","java","go","rust","api2","api3",
  "rest","graphql","grpc","ws","websocket","socket","realtime","push",
  "notify","notification","notifications","alert","alerts","webhook",
  "webhooks","callback","oauth","auth","sso","saml","ldap","ad","kerberos",
  "radius","vpn2","openvpn","wireguard","ipsec","ssl","tls","cert","certs",
  "pki","ca","ocsp","crl","acme","letsencrypt","smtp2","imap","pop","pop3",
  "mx3","relay","spam","antispam","dkim","spf","dmarc","postfix","dovecot",
  "roundcube","zimbra","office","o365","outlook","teams","slack","chat",
  "irc","matrix","xmpp","jabber","voip","sip","pbx","asterisk","phone",
  "tel","conference","meet","zoom","webex","gotomeeting","webrtc","video2",
  "stream","streaming","rtmp","hls","dash","live","broadcast","radio","tv",
  "camera","cam","cctv","nvr","dvr","security","sec","soc","ids","ips",
  "waf","modsec","crowdsec","fail2ban","guard","protect","scan","scanner",
  "nmap","pentest","bugbounty","hackerone","security2","incident","ir",
  "forensics","threat","intel","malware","sandbox2","cuckoo","yara",
  "sigma","suricata","snort","zeek","bro","pcap","netflow","sflow",
  "dns3","bind","unbound","pihole","adguard","blocklist","whitelist",
  "blacklist","acl","policy","compliance","audit2","risk","grc","iso",
  "pci","hipaa","gdpr","sox","nist","cis","stig","hardening","baseline",
  "patch","update","wsus","sccm","intune","mdm","endpoint","edr","xdr",
  "av","antivirus","defender","crowdstrike","sentinel","carbon","falcon",
  "cortex","sophos","eset","kaspersky","malwarebytes","clamav","openvas",
  "nessus","qualys","rapid7","tenable","burp","zap","nikto","sqlmap",
  "hydra","john","hashcat","responder","mimikatz","bloodhound","empire",
  "covenant","metasploit","cobalt","havoc","sliver","mythic","brute",
  "crack","exploit","payload","shell","reverse","bind2","stager","beacon",
  "implant","dropper","loader","crypter","packer","obfuscator","rat",
  "c2","cc","cnc","command","control","callback2","exfil","tunnel",
  "covert","steganography","crypto","encrypt","decrypt","hash","sign",
  "verify","key","keys","keystore","hsm","kms","secret","secrets",
  "password","passwords","credential","credentials","token","tokens",
  "session","sessions","cookie","cookies","jwt","oauth2","openid","oidc",
  "saml2","cas","passport","identity","iam","rbac","abac","permission",
  "role","user","users","account","accounts","profile","profiles",
  "member","members","group","groups","team","organization","org",
  "company","enterprise","business","corporate","partner","partners",
  "vendor","vendors","supplier","client","clients","customer","customers",
  "crm","erp","sap","salesforce","hubspot","zendesk","freshdesk","intercom",
  "analytics","stats","statistics","report","reports","reporting","bi",
  "tableau","powerbi","looker","superset","redash","metabase","data",
  "database","mysql","postgres","postgresql","mariadb","oracle","mssql2",
  "mongo","mongodb","redis","memcached","couchdb","cassandra","dynamodb",
  "rds","aurora","bigquery","snowflake","databricks","airflow","spark",
  "hadoop","kafka","rabbitmq","activemq","nats","pulsar","celery","worker",
  "queue","task","job","jobs","cron","scheduler","batch","etl","pipeline",
  "workflow","automation","automate","bot","bots","ai","ml","model",
  "inference","training","gpu","cuda","tensorrt","onnx","huggingface",
  "openai","anthropic","ollama2","llm","nlp","cv","vision","speech",
  "text","search","solr","sphinx","meilisearch","algolia","typesense",
  "geo","gis","map","maps","location","geocode","routing","navigation",
  "weather","time","clock","ntp","calendar","schedule","booking",
  "reservation","event","events","ticket2","order","orders","payment",
  "pay","checkout","cart","shop2","store2","ecommerce","marketplace",
  "auction","bid","trade","trading","exchange2","forex","crypto2","btc",
  "eth","defi","nft","blockchain","web3","ipfs","swarm","p2p","torrent",
  "tor","onion","i2p","proxy2","socks","shadowsocks","v2ray","trojan2",
  "clash","wireguard2","tailscale","zerotier","nebula","headscale",
  "mesh","overlay","vxlan","geneve","flannel","calico","cilium","istio",
  "envoy","linkerd","consul2","etcd","zookeeper","raft","paxos",
  "cluster","node2","master","worker2","agent","controller","operator",
  "helm","chart","template","manifest","yaml","json2","xml","csv","sql",
  "nosql","graphdb","neo4j","arangodb","dgraph","cayley","orient",
  "trello","asana","monday","clickup","notion","obsidian","roam",
];

// ═══════════════════════════════════════════════════════════════════════════════
// §4  IP OSINT
// ═══════════════════════════════════════════════════════════════════════════════

export function cidrToRange(cidr) {
  const [ip, bits] = cidr.split("/");
  const mask = bits ? parseInt(bits) : 32;
  const parts = ip.split(".").map(Number);
  const ipNum = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
  const hostBits = 32 - mask;
  const netMask = hostBits === 32 ? 0 : (~0 << hostBits) >>> 0;
  const network = (ipNum & netMask) >>> 0;
  const broadcast = (network | (~netMask >>> 0)) >>> 0;
  const numToIp = (n) => `${(n >>> 24) & 0xFF}.${(n >>> 16) & 0xFF}.${(n >>> 8) & 0xFF}.${n & 0xFF}`;
  return {
    network: numToIp(network), broadcast: numToIp(broadcast),
    firstHost: numToIp(network + 1), lastHost: numToIp(broadcast - 1),
    netmask: numToIp(netMask), totalHosts: Math.max(0, (broadcast - network - 1)),
    cidr, prefix: mask,
  };
}

const BOGON_RANGES = [
  { cidr: "0.0.0.0/8", desc: "This network" },
  { cidr: "10.0.0.0/8", desc: "Private (RFC 1918)" },
  { cidr: "100.64.0.0/10", desc: "Carrier-grade NAT (RFC 6598)" },
  { cidr: "127.0.0.0/8", desc: "Loopback" },
  { cidr: "169.254.0.0/16", desc: "Link-local" },
  { cidr: "172.16.0.0/12", desc: "Private (RFC 1918)" },
  { cidr: "192.0.0.0/24", desc: "IETF Protocol Assignments" },
  { cidr: "192.0.2.0/24", desc: "Documentation (TEST-NET-1)" },
  { cidr: "192.168.0.0/16", desc: "Private (RFC 1918)" },
  { cidr: "198.18.0.0/15", desc: "Benchmarking" },
  { cidr: "198.51.100.0/24", desc: "Documentation (TEST-NET-2)" },
  { cidr: "203.0.113.0/24", desc: "Documentation (TEST-NET-3)" },
  { cidr: "224.0.0.0/4", desc: "Multicast" },
  { cidr: "240.0.0.0/4", desc: "Reserved" },
  { cidr: "255.255.255.255/32", desc: "Broadcast" },
];

function ipToNum(ip) {
  const p = ip.split(".").map(Number);
  return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
}

export function isBogon(ip) {
  const num = ipToNum(ip);
  for (const b of BOGON_RANGES) {
    const range = cidrToRange(b.cidr);
    const netNum = ipToNum(range.network);
    const bcastNum = ipToNum(range.broadcast);
    if (num >= netNum && num <= bcastNum) return { bogon: true, range: b.cidr, desc: b.desc };
  }
  return { bogon: false };
}

export function reverseDNSPattern(ip) {
  const parts = ip.split(".").reverse();
  return parts.join(".") + ".in-addr.arpa";
}

// ═══════════════════════════════════════════════════════════════════════════════
// §5  SOCIAL MEDIA OSINT
// ═══════════════════════════════════════════════════════════════════════════════

export function generateUsernames(firstName, lastName) {
  const f = firstName.toLowerCase(); const l = lastName.toLowerCase();
  const fi = f[0] || ""; const li = l[0] || "";
  return [...new Set([
    `${f}${l}`, `${f}.${l}`, `${f}_${l}`, `${f}-${l}`, `${f}${li}`,
    `${fi}${l}`, `${l}${f}`, `${l}.${f}`, `${l}_${f}`, `${l}${fi}`,
    `${f}`, `${l}`, `${fi}${li}`, `${f}${l}1`, `${f}.${l}1`,
    `the${f}`, `real${f}`, `${f}official`, `${f}${l}official`,
    `x${f}`, `${f}x`, `${f}${l}99`, `${f}_${l}_`,
  ])];
}

export const PLATFORM_URLS = {
  twitter: (u) => `https://twitter.com/${u}`,
  x: (u) => `https://x.com/${u}`,
  instagram: (u) => `https://instagram.com/${u}`,
  facebook: (u) => `https://facebook.com/${u}`,
  linkedin: (u) => `https://linkedin.com/in/${u}`,
  github: (u) => `https://github.com/${u}`,
  reddit: (u) => `https://reddit.com/user/${u}`,
  tiktok: (u) => `https://tiktok.com/@${u}`,
  youtube: (u) => `https://youtube.com/@${u}`,
  twitch: (u) => `https://twitch.tv/${u}`,
  discord: (u) => `https://discord.com/users/${u}`,
  telegram: (u) => `https://t.me/${u}`,
  pinterest: (u) => `https://pinterest.com/${u}`,
  tumblr: (u) => `https://${u}.tumblr.com`,
  snapchat: (u) => `https://snapchat.com/add/${u}`,
  medium: (u) => `https://medium.com/@${u}`,
  devto: (u) => `https://dev.to/${u}`,
  hackernews: (u) => `https://news.ycombinator.com/user?id=${u}`,
  stackoverflow: (u) => `https://stackoverflow.com/users/?q=${u}`,
  keybase: (u) => `https://keybase.io/${u}`,
  mastodon: (u) => `https://mastodon.social/@${u}`,
  threads: (u) => `https://threads.net/@${u}`,
  bluesky: (u) => `https://bsky.app/profile/${u}.bsky.social`,
  spotify: (u) => `https://open.spotify.com/user/${u}`,
  soundcloud: (u) => `https://soundcloud.com/${u}`,
  behance: (u) => `https://behance.net/${u}`,
  dribbble: (u) => `https://dribbble.com/${u}`,
  flickr: (u) => `https://flickr.com/people/${u}`,
  vimeo: (u) => `https://vimeo.com/${u}`,
  gitlab: (u) => `https://gitlab.com/${u}`,
  bitbucket: (u) => `https://bitbucket.org/${u}`,
  npm: (u) => `https://npmjs.com/~${u}`,
  pypi: (u) => `https://pypi.org/user/${u}`,
  dockerhub: (u) => `https://hub.docker.com/u/${u}`,
  tryhackme: (u) => `https://tryhackme.com/p/${u}`,
  hackthebox: (u) => `https://app.hackthebox.com/users/${u}`,
};

// ═══════════════════════════════════════════════════════════════════════════════
// §6  GOOGLE DORKING LIBRARY
// ═══════════════════════════════════════════════════════════════════════════════

export const GOOGLE_DORKS = {
  file_discovery: [
    { dork: 'site:{domain} filetype:pdf', desc: "PDF documents on the target domain" },
    { dork: 'site:{domain} filetype:doc OR filetype:docx', desc: "Word documents" },
    { dork: 'site:{domain} filetype:xls OR filetype:xlsx', desc: "Spreadsheets" },
    { dork: 'site:{domain} filetype:ppt OR filetype:pptx', desc: "Presentations" },
    { dork: 'site:{domain} filetype:sql', desc: "SQL database dumps" },
    { dork: 'site:{domain} filetype:log', desc: "Log files" },
    { dork: 'site:{domain} filetype:bak', desc: "Backup files" },
    { dork: 'site:{domain} filetype:conf OR filetype:cfg', desc: "Configuration files" },
    { dork: 'site:{domain} filetype:env', desc: "Environment files (.env)" },
    { dork: 'site:{domain} filetype:xml', desc: "XML files" },
    { dork: 'site:{domain} filetype:json', desc: "JSON data files" },
    { dork: 'site:{domain} filetype:csv', desc: "CSV data exports" },
    { dork: 'site:{domain} filetype:txt "password"', desc: "Text files containing passwords" },
    { dork: 'site:{domain} filetype:key OR filetype:pem', desc: "Private key files" },
    { dork: 'site:{domain} filetype:rdp', desc: "Remote Desktop connection files" },
    { dork: 'site:{domain} filetype:pcap', desc: "Packet capture files" },
    { dork: 'site:{domain} filetype:tar.gz OR filetype:zip', desc: "Compressed archives" },
    { dork: 'site:{domain} ext:sql "INSERT INTO"', desc: "SQL dumps with data" },
    { dork: 'site:{domain} ext:yml OR ext:yaml', desc: "YAML configuration files" },
    { dork: 'site:{domain} filetype:swp OR filetype:swo', desc: "Vim swap files (temp edits)" },
  ],
  login_pages: [
    { dork: 'site:{domain} inurl:login', desc: "Login pages" },
    { dork: 'site:{domain} inurl:admin', desc: "Admin panels" },
    { dork: 'site:{domain} inurl:signin OR inurl:sign-in', desc: "Sign-in pages" },
    { dork: 'site:{domain} intitle:"login" OR intitle:"sign in"', desc: "Pages titled login/sign in" },
    { dork: 'site:{domain} inurl:dashboard', desc: "Dashboard pages" },
    { dork: 'site:{domain} inurl:wp-admin OR inurl:wp-login', desc: "WordPress admin" },
    { dork: 'site:{domain} inurl:administrator', desc: "Joomla admin" },
    { dork: 'site:{domain} inurl:user/login', desc: "Drupal login" },
    { dork: 'site:{domain} inurl:cpanel OR inurl:webmail', desc: "cPanel/Webmail" },
    { dork: 'site:{domain} inurl:phpmyadmin', desc: "phpMyAdmin" },
    { dork: 'site:{domain} inurl:_profiler', desc: "Symfony profiler" },
    { dork: 'site:{domain} inurl:elmah.axd', desc: "ELMAH error log (ASP.NET)" },
  ],
  credentials: [
    { dork: 'site:{domain} "password" filetype:txt', desc: "Passwords in text files" },
    { dork: 'site:{domain} "username" "password" filetype:log', desc: "Credentials in logs" },
    { dork: 'site:{domain} inurl:credentials', desc: "Credential pages" },
    { dork: 'site:{domain} "api_key" OR "apikey" OR "api key"', desc: "API keys exposed" },
    { dork: 'site:{domain} "AKIA" filetype:py OR filetype:js', desc: "AWS access keys in code" },
    { dork: 'site:{domain} "sk_live_" OR "pk_live_"', desc: "Stripe live keys" },
    { dork: 'site:{domain} "ghp_" OR "gho_" OR "github_pat_"', desc: "GitHub tokens" },
    { dork: 'site:{domain} "AIzaSy"', desc: "Google API keys" },
    { dork: 'site:{domain} "SG." filetype:env', desc: "SendGrid API keys" },
    { dork: 'site:{domain} "xoxb-" OR "xoxp-"', desc: "Slack tokens" },
    { dork: 'site:{domain} "BEGIN RSA PRIVATE KEY"', desc: "RSA private keys" },
    { dork: 'site:{domain} "jdbc:mysql://" OR "jdbc:postgresql://"', desc: "Database connection strings" },
    { dork: 'site:{domain} "mongodb+srv://" OR "mongodb://"', desc: "MongoDB connection strings" },
    { dork: 'site:{domain} intext:"DB_PASSWORD" filetype:env', desc: "Database passwords in .env" },
    { dork: 'site:pastebin.com "{domain}"', desc: "Pastes mentioning the domain" },
    { dork: 'site:github.com "{domain}" password', desc: "Passwords on GitHub mentioning domain" },
    { dork: 'site:trello.com "{domain}"', desc: "Trello boards mentioning domain" },
  ],
  config_files: [
    { dork: 'site:{domain} inurl:web.config', desc: "ASP.NET web.config" },
    { dork: 'site:{domain} inurl:.htaccess', desc: "Apache .htaccess" },
    { dork: 'site:{domain} inurl:crossdomain.xml', desc: "Flash crossdomain policy" },
    { dork: 'site:{domain} inurl:robots.txt', desc: "Robots.txt" },
    { dork: 'site:{domain} inurl:sitemap.xml', desc: "Sitemap" },
    { dork: 'site:{domain} inurl:.git', desc: "Exposed .git directory" },
    { dork: 'site:{domain} inurl:.svn', desc: "Exposed .svn directory" },
    { dork: 'site:{domain} inurl:.env', desc: "Environment file" },
    { dork: 'site:{domain} inurl:wp-config.php', desc: "WordPress config" },
    { dork: 'site:{domain} inurl:config.php', desc: "PHP config file" },
    { dork: 'site:{domain} inurl:settings.py', desc: "Django settings" },
    { dork: 'site:{domain} inurl:application.properties', desc: "Spring Boot config" },
    { dork: 'site:{domain} inurl:docker-compose', desc: "Docker Compose files" },
    { dork: 'site:{domain} inurl:Dockerfile', desc: "Dockerfiles" },
    { dork: 'site:{domain} inurl:Jenkinsfile', desc: "Jenkins pipeline" },
    { dork: 'site:{domain} inurl:.travis.yml', desc: "Travis CI config" },
    { dork: 'site:{domain} inurl:package.json', desc: "Node.js package.json" },
    { dork: 'site:{domain} inurl:composer.json', desc: "PHP Composer config" },
  ],
  error_messages: [
    { dork: 'site:{domain} "Fatal error" OR "Parse error"', desc: "PHP errors" },
    { dork: 'site:{domain} "Traceback (most recent call last)"', desc: "Python tracebacks" },
    { dork: 'site:{domain} "Exception in thread" OR "java.lang."', desc: "Java stack traces" },
    { dork: 'site:{domain} "Warning:" "mysql_" OR "mysqli_"', desc: "MySQL warnings" },
    { dork: 'site:{domain} "ORA-" -site:docs.oracle.com', desc: "Oracle DB errors" },
    { dork: 'site:{domain} "pg_query" OR "pg_connect"', desc: "PostgreSQL errors" },
    { dork: 'site:{domain} "Microsoft OLE DB" OR "ODBC"', desc: "MSSQL errors" },
    { dork: 'site:{domain} "Server Error in" "Application"', desc: "ASP.NET errors" },
    { dork: 'site:{domain} inurl:trace.axd', desc: "ASP.NET trace" },
    { dork: 'site:{domain} "DEBUG = True"', desc: "Django debug mode" },
    { dork: 'site:{domain} "Error 500" OR "Internal Server Error"', desc: "500 errors" },
    { dork: 'site:{domain} "syntax error" OR "undefined variable"', desc: "Code errors" },
  ],
  directory_listing: [
    { dork: 'site:{domain} intitle:"index of"', desc: "Open directory listings" },
    { dork: 'site:{domain} intitle:"index of" "parent directory"', desc: "Apache directory listing" },
    { dork: 'site:{domain} intitle:"index of" inurl:backup', desc: "Backup directories" },
    { dork: 'site:{domain} intitle:"index of" inurl:upload', desc: "Upload directories" },
    { dork: 'site:{domain} intitle:"index of" "wp-content"', desc: "WordPress content directory" },
    { dork: 'site:{domain} intitle:"index of" ".sql"', desc: "Directories with SQL files" },
    { dork: 'site:{domain} intitle:"index of" ".log"', desc: "Directories with log files" },
  ],
  vulnerable_software: [
    { dork: 'site:{domain} "powered by" "WordPress" inurl:readme.html', desc: "WordPress readme (version leak)" },
    { dork: 'site:{domain} inurl:CHANGELOG.txt', desc: "Drupal changelog (version leak)" },
    { dork: 'site:{domain} "X-Powered-By" ext:php', desc: "PHP version headers" },
    { dork: 'site:{domain} inurl:server-status', desc: "Apache server-status" },
    { dork: 'site:{domain} inurl:server-info', desc: "Apache server-info" },
    { dork: 'site:{domain} inurl:info.php OR inurl:phpinfo.php', desc: "PHP info page" },
    { dork: 'site:{domain} "Tomcat" intitle:"Apache Tomcat"', desc: "Tomcat default page" },
    { dork: 'site:{domain} "IIS" intitle:"Microsoft Internet Information Services"', desc: "IIS default page" },
    { dork: 'site:{domain} inurl:jmx-console', desc: "JBoss JMX console" },
    { dork: 'site:{domain} inurl:manager/html', desc: "Tomcat manager" },
    { dork: 'site:{domain} intitle:"Swagger UI"', desc: "Swagger API documentation" },
    { dork: 'site:{domain} inurl:graphql', desc: "GraphQL endpoint" },
    { dork: 'site:{domain} inurl:api/v1 OR inurl:api/v2', desc: "API version endpoints" },
  ],
};

export function generateDorks(domain, categories) {
  const results = [];
  const cats = categories || Object.keys(GOOGLE_DORKS);
  for (const cat of cats) {
    const dorks = GOOGLE_DORKS[cat];
    if (!dorks) continue;
    for (const d of dorks) {
      results.push({
        category: cat,
        query: d.dork.replace(/\{domain\}/g, domain),
        description: d.desc,
        url: `https://www.google.com/search?q=${encodeURIComponent(d.dork.replace(/\{domain\}/g, domain))}`,
      });
    }
  }
  return results;
}

// ═══════════════════════════════════════════════════════════════════════════════
// §7  METADATA EXTRACTION
// ═══════════════════════════════════════════════════════════════════════════════

export function parseExif(buf) {
  const dv = new DataView(buf instanceof ArrayBuffer ? buf : buf.buffer);
  const result = { found: false, fields: {} };
  if (dv.byteLength < 4) return result;

  // JPEG check
  if (dv.getUint8(0) !== 0xFF || dv.getUint8(1) !== 0xD8) return result;

  let offset = 2;
  while (offset + 4 < dv.byteLength) {
    const marker = dv.getUint16(offset);
    if (marker === 0xFFE1) { // APP1 = EXIF
      const length = dv.getUint16(offset + 2);
      const exifStart = offset + 4;
      if (exifStart + 6 > dv.byteLength) break;
      const exifStr = String.fromCharCode(dv.getUint8(exifStart), dv.getUint8(exifStart + 1),
        dv.getUint8(exifStart + 2), dv.getUint8(exifStart + 3));
      if (exifStr !== "Exif") break;

      const tiffStart = exifStart + 6;
      if (tiffStart + 8 > dv.byteLength) break;
      const byteOrder = dv.getUint16(tiffStart);
      const le = byteOrder === 0x4949; // II = little-endian

      const readU16 = (o) => dv.getUint16(o, le);
      const readU32 = (o) => dv.getUint32(o, le);

      const ifdOffset = readU32(tiffStart + 4);
      const ifd0Start = tiffStart + ifdOffset;
      if (ifd0Start + 2 > dv.byteLength) break;

      const numEntries = readU16(ifd0Start);
      const EXIF_TAGS = {
        0x010F: "Make", 0x0110: "Model", 0x0112: "Orientation",
        0x011A: "XResolution", 0x011B: "YResolution",
        0x0131: "Software", 0x0132: "DateTime",
        0x013B: "Artist", 0x8298: "Copyright",
        0x8769: "ExifIFDPointer", 0x8825: "GPSInfoIFDPointer",
        0xA002: "PixelXDimension", 0xA003: "PixelYDimension",
        0x9003: "DateTimeOriginal", 0x9004: "DateTimeDigitized",
        0x920A: "FocalLength", 0x829A: "ExposureTime",
        0x829D: "FNumber", 0x8827: "ISOSpeedRatings",
      };

      for (let i = 0; i < numEntries && i < 100; i++) {
        const entryOff = ifd0Start + 2 + i * 12;
        if (entryOff + 12 > dv.byteLength) break;
        const tag = readU16(entryOff);
        const type = readU16(entryOff + 2);
        const count = readU32(entryOff + 4);
        const valueOff = entryOff + 8;

        const tagName = EXIF_TAGS[tag] || `Tag_0x${tag.toString(16)}`;
        let value;

        if (type === 2) { // ASCII
          const strOff = count > 4 ? tiffStart + readU32(valueOff) : valueOff;
          if (strOff + count <= dv.byteLength) {
            const chars = [];
            for (let j = 0; j < count - 1 && strOff + j < dv.byteLength; j++)
              chars.push(String.fromCharCode(dv.getUint8(strOff + j)));
            value = chars.join("");
          }
        } else if (type === 3) { // SHORT
          value = readU16(valueOff);
        } else if (type === 4) { // LONG
          value = readU32(valueOff);
        }

        if (value !== undefined) result.fields[tagName] = value;
      }

      result.found = true;
      break;
    }
    if ((marker & 0xFF00) !== 0xFF00) break;
    const segLen = dv.getUint16(offset + 2);
    offset += 2 + segLen;
  }

  return result;
}

export function parsePDFMeta(buf) {
  const text = new TextDecoder("latin1").decode(buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf);
  const result = {};
  const infoMatch = text.match(/\/Info\s+(\d+)\s+0\s+R/);
  const patterns = [
    [/\/Title\s*\(([^)]*)\)/, "title"],
    [/\/Author\s*\(([^)]*)\)/, "author"],
    [/\/Creator\s*\(([^)]*)\)/, "creator"],
    [/\/Producer\s*\(([^)]*)\)/, "producer"],
    [/\/CreationDate\s*\(([^)]*)\)/, "creationDate"],
    [/\/ModDate\s*\(([^)]*)\)/, "modDate"],
    [/\/Subject\s*\(([^)]*)\)/, "subject"],
    [/\/Keywords\s*\(([^)]*)\)/, "keywords"],
  ];
  for (const [re, key] of patterns) {
    const m = text.match(re);
    if (m) result[key] = m[1];
  }
  return result;
}

// ═══════════════════════════════════════════════════════════════════════════════
// §8  GEOLOCATION TOOLS
// ═══════════════════════════════════════════════════════════════════════════════

export function dmsToDecimal(degrees, minutes, seconds, direction) {
  let dd = Math.abs(degrees) + minutes / 60 + seconds / 3600;
  if (direction === "S" || direction === "W") dd *= -1;
  return Math.round(dd * 1000000) / 1000000;
}

export function decimalToDMS(decimal, isLat) {
  const dir = isLat ? (decimal >= 0 ? "N" : "S") : (decimal >= 0 ? "E" : "W");
  const abs = Math.abs(decimal);
  const deg = Math.floor(abs);
  const minFloat = (abs - deg) * 60;
  const min = Math.floor(minFloat);
  const sec = Math.round((minFloat - min) * 60 * 100) / 100;
  return { degrees: deg, minutes: min, seconds: sec, direction: dir, string: `${deg}°${min}'${sec}"${dir}` };
}

export function haversineDistance(lat1, lon1, lat2, lon2) {
  const R = 6371; // km
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat / 2) ** 2 +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

// ═══════════════════════════════════════════════════════════════════════════════
// §9  COUNTRY CODE DATABASE (ISO 3166)
// ═══════════════════════════════════════════════════════════════════════════════

export const COUNTRIES = [
  {c:"AF",n:"Afghanistan",r:"Asia"},{c:"AL",n:"Albania",r:"Europe"},{c:"DZ",n:"Algeria",r:"Africa"},
  {c:"AD",n:"Andorra",r:"Europe"},{c:"AO",n:"Angola",r:"Africa"},{c:"AR",n:"Argentina",r:"Americas"},
  {c:"AM",n:"Armenia",r:"Asia"},{c:"AU",n:"Australia",r:"Oceania"},{c:"AT",n:"Austria",r:"Europe"},
  {c:"AZ",n:"Azerbaijan",r:"Asia"},{c:"BH",n:"Bahrain",r:"Asia"},{c:"BD",n:"Bangladesh",r:"Asia"},
  {c:"BY",n:"Belarus",r:"Europe"},{c:"BE",n:"Belgium",r:"Europe"},{c:"BZ",n:"Belize",r:"Americas"},
  {c:"BJ",n:"Benin",r:"Africa"},{c:"BT",n:"Bhutan",r:"Asia"},{c:"BO",n:"Bolivia",r:"Americas"},
  {c:"BA",n:"Bosnia and Herzegovina",r:"Europe"},{c:"BW",n:"Botswana",r:"Africa"},
  {c:"BR",n:"Brazil",r:"Americas"},{c:"BN",n:"Brunei",r:"Asia"},{c:"BG",n:"Bulgaria",r:"Europe"},
  {c:"BF",n:"Burkina Faso",r:"Africa"},{c:"BI",n:"Burundi",r:"Africa"},{c:"KH",n:"Cambodia",r:"Asia"},
  {c:"CM",n:"Cameroon",r:"Africa"},{c:"CA",n:"Canada",r:"Americas"},{c:"CF",n:"Central African Republic",r:"Africa"},
  {c:"TD",n:"Chad",r:"Africa"},{c:"CL",n:"Chile",r:"Americas"},{c:"CN",n:"China",r:"Asia"},
  {c:"CO",n:"Colombia",r:"Americas"},{c:"CG",n:"Congo",r:"Africa"},{c:"CD",n:"DR Congo",r:"Africa"},
  {c:"CR",n:"Costa Rica",r:"Americas"},{c:"HR",n:"Croatia",r:"Europe"},{c:"CU",n:"Cuba",r:"Americas"},
  {c:"CY",n:"Cyprus",r:"Europe"},{c:"CZ",n:"Czechia",r:"Europe"},{c:"DK",n:"Denmark",r:"Europe"},
  {c:"DJ",n:"Djibouti",r:"Africa"},{c:"DO",n:"Dominican Republic",r:"Americas"},
  {c:"EC",n:"Ecuador",r:"Americas"},{c:"EG",n:"Egypt",r:"Africa"},{c:"SV",n:"El Salvador",r:"Americas"},
  {c:"GQ",n:"Equatorial Guinea",r:"Africa"},{c:"ER",n:"Eritrea",r:"Africa"},{c:"EE",n:"Estonia",r:"Europe"},
  {c:"SZ",n:"Eswatini",r:"Africa"},{c:"ET",n:"Ethiopia",r:"Africa"},{c:"FI",n:"Finland",r:"Europe"},
  {c:"FR",n:"France",r:"Europe"},{c:"GA",n:"Gabon",r:"Africa"},{c:"GM",n:"Gambia",r:"Africa"},
  {c:"GE",n:"Georgia",r:"Asia"},{c:"DE",n:"Germany",r:"Europe"},{c:"GH",n:"Ghana",r:"Africa"},
  {c:"GR",n:"Greece",r:"Europe"},{c:"GT",n:"Guatemala",r:"Americas"},{c:"GN",n:"Guinea",r:"Africa"},
  {c:"GY",n:"Guyana",r:"Americas"},{c:"HT",n:"Haiti",r:"Americas"},{c:"HN",n:"Honduras",r:"Americas"},
  {c:"HU",n:"Hungary",r:"Europe"},{c:"IS",n:"Iceland",r:"Europe"},{c:"IN",n:"India",r:"Asia"},
  {c:"ID",n:"Indonesia",r:"Asia"},{c:"IR",n:"Iran",r:"Asia"},{c:"IQ",n:"Iraq",r:"Asia"},
  {c:"IE",n:"Ireland",r:"Europe"},{c:"IL",n:"Israel",r:"Asia"},{c:"IT",n:"Italy",r:"Europe"},
  {c:"JM",n:"Jamaica",r:"Americas"},{c:"JP",n:"Japan",r:"Asia"},{c:"JO",n:"Jordan",r:"Asia"},
  {c:"KZ",n:"Kazakhstan",r:"Asia"},{c:"KE",n:"Kenya",r:"Africa"},{c:"KP",n:"North Korea",r:"Asia"},
  {c:"KR",n:"South Korea",r:"Asia"},{c:"KW",n:"Kuwait",r:"Asia"},{c:"KG",n:"Kyrgyzstan",r:"Asia"},
  {c:"LA",n:"Laos",r:"Asia"},{c:"LV",n:"Latvia",r:"Europe"},{c:"LB",n:"Lebanon",r:"Asia"},
  {c:"LS",n:"Lesotho",r:"Africa"},{c:"LR",n:"Liberia",r:"Africa"},{c:"LY",n:"Libya",r:"Africa"},
  {c:"LI",n:"Liechtenstein",r:"Europe"},{c:"LT",n:"Lithuania",r:"Europe"},{c:"LU",n:"Luxembourg",r:"Europe"},
  {c:"MG",n:"Madagascar",r:"Africa"},{c:"MW",n:"Malawi",r:"Africa"},{c:"MY",n:"Malaysia",r:"Asia"},
  {c:"MV",n:"Maldives",r:"Asia"},{c:"ML",n:"Mali",r:"Africa"},{c:"MT",n:"Malta",r:"Europe"},
  {c:"MR",n:"Mauritania",r:"Africa"},{c:"MU",n:"Mauritius",r:"Africa"},{c:"MX",n:"Mexico",r:"Americas"},
  {c:"MD",n:"Moldova",r:"Europe"},{c:"MC",n:"Monaco",r:"Europe"},{c:"MN",n:"Mongolia",r:"Asia"},
  {c:"ME",n:"Montenegro",r:"Europe"},{c:"MA",n:"Morocco",r:"Africa"},{c:"MZ",n:"Mozambique",r:"Africa"},
  {c:"MM",n:"Myanmar",r:"Asia"},{c:"NA",n:"Namibia",r:"Africa"},{c:"NP",n:"Nepal",r:"Asia"},
  {c:"NL",n:"Netherlands",r:"Europe"},{c:"NZ",n:"New Zealand",r:"Oceania"},{c:"NI",n:"Nicaragua",r:"Americas"},
  {c:"NE",n:"Niger",r:"Africa"},{c:"NG",n:"Nigeria",r:"Africa"},{c:"MK",n:"North Macedonia",r:"Europe"},
  {c:"NO",n:"Norway",r:"Europe"},{c:"OM",n:"Oman",r:"Asia"},{c:"PK",n:"Pakistan",r:"Asia"},
  {c:"PA",n:"Panama",r:"Americas"},{c:"PG",n:"Papua New Guinea",r:"Oceania"},{c:"PY",n:"Paraguay",r:"Americas"},
  {c:"PE",n:"Peru",r:"Americas"},{c:"PH",n:"Philippines",r:"Asia"},{c:"PL",n:"Poland",r:"Europe"},
  {c:"PT",n:"Portugal",r:"Europe"},{c:"QA",n:"Qatar",r:"Asia"},{c:"RO",n:"Romania",r:"Europe"},
  {c:"RU",n:"Russia",r:"Europe"},{c:"RW",n:"Rwanda",r:"Africa"},{c:"SA",n:"Saudi Arabia",r:"Asia"},
  {c:"SN",n:"Senegal",r:"Africa"},{c:"RS",n:"Serbia",r:"Europe"},{c:"SG",n:"Singapore",r:"Asia"},
  {c:"SK",n:"Slovakia",r:"Europe"},{c:"SI",n:"Slovenia",r:"Europe"},{c:"SO",n:"Somalia",r:"Africa"},
  {c:"ZA",n:"South Africa",r:"Africa"},{c:"SS",n:"South Sudan",r:"Africa"},{c:"ES",n:"Spain",r:"Europe"},
  {c:"LK",n:"Sri Lanka",r:"Asia"},{c:"SD",n:"Sudan",r:"Africa"},{c:"SR",n:"Suriname",r:"Americas"},
  {c:"SE",n:"Sweden",r:"Europe"},{c:"CH",n:"Switzerland",r:"Europe"},{c:"SY",n:"Syria",r:"Asia"},
  {c:"TW",n:"Taiwan",r:"Asia"},{c:"TJ",n:"Tajikistan",r:"Asia"},{c:"TZ",n:"Tanzania",r:"Africa"},
  {c:"TH",n:"Thailand",r:"Asia"},{c:"TG",n:"Togo",r:"Africa"},{c:"TT",n:"Trinidad and Tobago",r:"Americas"},
  {c:"TN",n:"Tunisia",r:"Africa"},{c:"TR",n:"Turkey",r:"Asia"},{c:"TM",n:"Turkmenistan",r:"Asia"},
  {c:"UG",n:"Uganda",r:"Africa"},{c:"UA",n:"Ukraine",r:"Europe"},{c:"AE",n:"UAE",r:"Asia"},
  {c:"GB",n:"United Kingdom",r:"Europe"},{c:"US",n:"United States",r:"Americas"},
  {c:"UY",n:"Uruguay",r:"Americas"},{c:"UZ",n:"Uzbekistan",r:"Asia"},{c:"VE",n:"Venezuela",r:"Americas"},
  {c:"VN",n:"Vietnam",r:"Asia"},{c:"YE",n:"Yemen",r:"Asia"},{c:"ZM",n:"Zambia",r:"Africa"},
  {c:"ZW",n:"Zimbabwe",r:"Africa"},
];

// ═══════════════════════════════════════════════════════════════════════════════
// §10  PHONE NUMBER ANALYZER
// ═══════════════════════════════════════════════════════════════════════════════

export const PHONE_COUNTRY_CODES = [
  {code:"+1",country:"US/CA",name:"United States / Canada"},{code:"+7",country:"RU",name:"Russia"},
  {code:"+20",country:"EG",name:"Egypt"},{code:"+27",country:"ZA",name:"South Africa"},
  {code:"+30",country:"GR",name:"Greece"},{code:"+31",country:"NL",name:"Netherlands"},
  {code:"+32",country:"BE",name:"Belgium"},{code:"+33",country:"FR",name:"France"},
  {code:"+34",country:"ES",name:"Spain"},{code:"+36",country:"HU",name:"Hungary"},
  {code:"+39",country:"IT",name:"Italy"},{code:"+40",country:"RO",name:"Romania"},
  {code:"+41",country:"CH",name:"Switzerland"},{code:"+43",country:"AT",name:"Austria"},
  {code:"+44",country:"GB",name:"United Kingdom"},{code:"+45",country:"DK",name:"Denmark"},
  {code:"+46",country:"SE",name:"Sweden"},{code:"+47",country:"NO",name:"Norway"},
  {code:"+48",country:"PL",name:"Poland"},{code:"+49",country:"DE",name:"Germany"},
  {code:"+51",country:"PE",name:"Peru"},{code:"+52",country:"MX",name:"Mexico"},
  {code:"+53",country:"CU",name:"Cuba"},{code:"+54",country:"AR",name:"Argentina"},
  {code:"+55",country:"BR",name:"Brazil"},{code:"+56",country:"CL",name:"Chile"},
  {code:"+57",country:"CO",name:"Colombia"},{code:"+58",country:"VE",name:"Venezuela"},
  {code:"+60",country:"MY",name:"Malaysia"},{code:"+61",country:"AU",name:"Australia"},
  {code:"+62",country:"ID",name:"Indonesia"},{code:"+63",country:"PH",name:"Philippines"},
  {code:"+64",country:"NZ",name:"New Zealand"},{code:"+65",country:"SG",name:"Singapore"},
  {code:"+66",country:"TH",name:"Thailand"},{code:"+81",country:"JP",name:"Japan"},
  {code:"+82",country:"KR",name:"South Korea"},{code:"+84",country:"VN",name:"Vietnam"},
  {code:"+86",country:"CN",name:"China"},{code:"+90",country:"TR",name:"Turkey"},
  {code:"+91",country:"IN",name:"India"},{code:"+92",country:"PK",name:"Pakistan"},
  {code:"+93",country:"AF",name:"Afghanistan"},{code:"+94",country:"LK",name:"Sri Lanka"},
  {code:"+95",country:"MM",name:"Myanmar"},{code:"+98",country:"IR",name:"Iran"},
  {code:"+212",country:"MA",name:"Morocco"},{code:"+213",country:"DZ",name:"Algeria"},
  {code:"+216",country:"TN",name:"Tunisia"},{code:"+218",country:"LY",name:"Libya"},
  {code:"+220",country:"GM",name:"Gambia"},{code:"+234",country:"NG",name:"Nigeria"},
  {code:"+254",country:"KE",name:"Kenya"},{code:"+255",country:"TZ",name:"Tanzania"},
  {code:"+256",country:"UG",name:"Uganda"},{code:"+260",country:"ZM",name:"Zambia"},
  {code:"+263",country:"ZW",name:"Zimbabwe"},{code:"+351",country:"PT",name:"Portugal"},
  {code:"+353",country:"IE",name:"Ireland"},{code:"+354",country:"IS",name:"Iceland"},
  {code:"+358",country:"FI",name:"Finland"},{code:"+370",country:"LT",name:"Lithuania"},
  {code:"+371",country:"LV",name:"Latvia"},{code:"+372",country:"EE",name:"Estonia"},
  {code:"+380",country:"UA",name:"Ukraine"},{code:"+381",country:"RS",name:"Serbia"},
  {code:"+420",country:"CZ",name:"Czechia"},{code:"+421",country:"SK",name:"Slovakia"},
  {code:"+852",country:"HK",name:"Hong Kong"},{code:"+855",country:"KH",name:"Cambodia"},
  {code:"+880",country:"BD",name:"Bangladesh"},{code:"+886",country:"TW",name:"Taiwan"},
  {code:"+960",country:"MV",name:"Maldives"},{code:"+961",country:"LB",name:"Lebanon"},
  {code:"+962",country:"JO",name:"Jordan"},{code:"+964",country:"IQ",name:"Iraq"},
  {code:"+965",country:"KW",name:"Kuwait"},{code:"+966",country:"SA",name:"Saudi Arabia"},
  {code:"+968",country:"OM",name:"Oman"},{code:"+970",country:"PS",name:"Palestine"},
  {code:"+971",country:"AE",name:"UAE"},{code:"+972",country:"IL",name:"Israel"},
  {code:"+974",country:"QA",name:"Qatar"},{code:"+977",country:"NP",name:"Nepal"},
  {code:"+992",country:"TJ",name:"Tajikistan"},{code:"+993",country:"TM",name:"Turkmenistan"},
  {code:"+994",country:"AZ",name:"Azerbaijan"},{code:"+995",country:"GE",name:"Georgia"},
  {code:"+996",country:"KG",name:"Kyrgyzstan"},{code:"+998",country:"UZ",name:"Uzbekistan"},
];

export function analyzePhoneNumber(number) {
  const clean = number.replace(/[\s\-().]/g, "");
  const result = { raw: number, cleaned: clean, valid: false };

  if (!/^\+?\d{7,15}$/.test(clean)) return result;

  result.valid = true;
  result.e164 = clean.startsWith("+") ? clean : `+${clean}`;

  // Find country code
  const withPlus = result.e164;
  for (const cc of PHONE_COUNTRY_CODES.sort((a, b) => b.code.length - a.code.length)) {
    if (withPlus.startsWith(cc.code)) {
      result.countryCode = cc.code;
      result.country = cc.country;
      result.countryName = cc.name;
      result.nationalNumber = withPlus.slice(cc.code.length);
      break;
    }
  }

  return result;
}

// ═══════════════════════════════════════════════════════════════════════════════
// §11  ORGANIZATION MAPPER
// ═══════════════════════════════════════════════════════════════════════════════

export function buildRelationshipGraph(entities) {
  const nodes = new Map();
  const edges = [];

  for (const e of entities) {
    if (!nodes.has(e.id)) nodes.set(e.id, { id: e.id, type: e.type, label: e.label, data: e.data || {} });
  }

  for (const e of entities) {
    if (e.links) {
      for (const link of e.links) {
        if (nodes.has(link.target)) {
          edges.push({ from: e.id, to: link.target, relation: link.relation || "related" });
        }
      }
    }
  }

  return { nodes: [...nodes.values()], edges, stats: { nodeCount: nodes.size, edgeCount: edges.length } };
}

// ═══════════════════════════════════════════════════════════════════════════════
// §12  OSINT REPORT TEMPLATE
// ═══════════════════════════════════════════════════════════════════════════════

export function generateOSINTReport(target, findings) {
  const lines = [
    `# OSINT Report: ${target}`,
    `Generated: ${new Date().toISOString()}`,
    `Tool: Darknode OSINT Engine`,
    ``,
    `## Target Summary`,
    `- Target: ${target}`,
    `- Type: ${findings.targetType || "Unknown"}`,
    `- Risk Level: ${findings.riskLevel || "Not assessed"}`,
    ``,
  ];

  if (findings.domains) {
    lines.push(`## Domain Intelligence`);
    for (const d of findings.domains) {
      lines.push(`- ${d.domain}: ${d.registrar || ""} | Age: ${d.age || "Unknown"} | NS: ${(d.nameServers || []).join(", ")}`);
    }
    lines.push(``);
  }

  if (findings.emails) {
    lines.push(`## Email Addresses`);
    for (const e of findings.emails) lines.push(`- ${e}`);
    lines.push(``);
  }

  if (findings.ips) {
    lines.push(`## IP Addresses`);
    for (const ip of findings.ips) lines.push(`- ${ip.address}: ${ip.location || ""} | ${ip.org || ""}`);
    lines.push(``);
  }

  if (findings.socialMedia) {
    lines.push(`## Social Media Profiles`);
    for (const s of findings.socialMedia) lines.push(`- ${s.platform}: ${s.url} ${s.verified ? "(verified)" : ""}`);
    lines.push(``);
  }

  if (findings.exposedData) {
    lines.push(`## Exposed Data`);
    for (const d of findings.exposedData) lines.push(`- [${d.severity}] ${d.description}`);
    lines.push(``);
  }

  lines.push(`## Recommendations`);
  lines.push(`- Review and remediate any exposed credentials or sensitive files`);
  lines.push(`- Implement SPF, DKIM, and DMARC for email authentication`);
  lines.push(`- Remove unnecessary public-facing services and directory listings`);
  lines.push(`- Monitor for data leaks on paste sites and code repositories`);
  lines.push(``);
  lines.push(`---`);
  lines.push(`*This report was generated automatically by Darknode OSINT Engine.*`);
  lines.push(`*Findings should be verified manually before action.*`);

  return lines.join("\n");
}

// ═══════════════════════════════════════════════════════════════════════════════
// §13  DATA BREACH CHECKER
// ═══════════════════════════════════════════════════════════════════════════════

export function buildBreachCheckURL(email) {
  return {
    hibp: `https://haveibeenpwned.com/account/${encodeURIComponent(email)}`,
    dehashed: `https://dehashed.com/search?query=${encodeURIComponent(email)}`,
    intelx: `https://intelx.io/?s=${encodeURIComponent(email)}`,
    leakcheck: `https://leakcheck.io/check/${encodeURIComponent(email)}`,
  };
}

export function buildDomainBreachCheckURL(domain) {
  return {
    hibp: `https://haveibeenpwned.com/DomainSearch?domain=${encodeURIComponent(domain)}`,
    dehashed: `https://dehashed.com/search?query=${encodeURIComponent(domain)}`,
    intelx: `https://intelx.io/?s=${encodeURIComponent(domain)}`,
    crtsh: `https://crt.sh/?q=${encodeURIComponent(domain)}`,
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// §14  SHODAN / CENSYS QUERY BUILDER
// ═══════════════════════════════════════════════════════════════════════════════

export const SHODAN_QUERIES = {
  webcams: [
    { q: 'title:"webcam" has_screenshot:true', desc: "Webcams with screenshots" },
    { q: 'product:"webcamXP" OR product:"Yawcam"', desc: "Known webcam software" },
    { q: 'title:"Live View / - AXIS" OR title:"Network Camera"', desc: "Network cameras" },
  ],
  databases: [
    { q: 'port:27017 "MongoDB"', desc: "MongoDB instances" },
    { q: 'port:9200 "elasticsearch"', desc: "Elasticsearch clusters" },
    { q: 'port:6379 "redis_version"', desc: "Redis instances" },
    { q: 'port:5432 "PostgreSQL"', desc: "PostgreSQL databases" },
    { q: 'port:3306 "MySQL"', desc: "MySQL databases" },
    { q: 'port:9042 "cassandra"', desc: "Cassandra clusters" },
    { q: '"CouchDB" port:5984', desc: "CouchDB instances" },
  ],
  ics_scada: [
    { q: 'port:502 "Modbus"', desc: "Modbus SCADA devices" },
    { q: 'port:47808 "BACnet"', desc: "BACnet building automation" },
    { q: 'port:44818 "EtherNet/IP"', desc: "EtherNet/IP industrial" },
    { q: '"Siemens" port:102', desc: "Siemens S7 PLCs" },
    { q: '"Schneider Electric"', desc: "Schneider Electric devices" },
  ],
  vulnerable: [
    { q: 'http.favicon.hash:-335242539', desc: "VMware vCenter (potential CVE-2021-21985)" },
    { q: '"X-Powered-By: Express" "X-RateLimit"', desc: "Rate-limited Express.js APIs" },
    { q: 'http.title:"Dashboard [Jenkins]"', desc: "Jenkins dashboards" },
    { q: '"Docker" port:2375', desc: "Exposed Docker daemons" },
    { q: '"Kubernetes" port:10250', desc: "Exposed Kubernetes kubelet" },
    { q: 'title:"Grafana" port:3000', desc: "Grafana dashboards" },
    { q: '"GitLab" port:80 OR port:443', desc: "GitLab instances" },
  ],
  network: [
    { q: 'cisco "last-modified"', desc: "Cisco devices" },
    { q: '"MikroTik" port:8291', desc: "MikroTik routers" },
    { q: 'title:"Ubiquiti" OR "UniFi"', desc: "Ubiquiti network devices" },
    { q: '"FortiGate" OR "Fortinet"', desc: "Fortinet firewalls" },
    { q: '"PAN-OS" OR "Palo Alto"', desc: "Palo Alto firewalls" },
  ],
};

export function buildShodanURL(query) {
  return `https://www.shodan.io/search?query=${encodeURIComponent(query)}`;
}

// ═══════════════════════════════════════════════════════════════════════════════
// §15  DARK WEB PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

export function isOnionAddress(url) {
  return /\.onion(?:\/|$)/i.test(url);
}

export function validateOnionV3(address) {
  const match = address.match(/([a-z2-7]{56})\.onion/i);
  if (!match) return { valid: false, version: null };
  return { valid: true, version: 3, address: match[1] + ".onion" };
}

export const PASTE_SITES = [
  { name: "Pastebin", url: "https://pastebin.com", searchPattern: "https://pastebin.com/search?q={query}" },
  { name: "Ghostbin", url: "https://ghostbin.com", searchPattern: null },
  { name: "GitHub Gist", url: "https://gist.github.com", searchPattern: "https://gist.github.com/search?q={query}" },
  { name: "Rentry", url: "https://rentry.co", searchPattern: null },
  { name: "dpaste", url: "https://dpaste.org", searchPattern: null },
  { name: "PrivateBin", url: "https://privatebin.net", searchPattern: null },
  { name: "PasteBin (search via Google)", url: "https://pastebin.com", searchPattern: "https://www.google.com/search?q=site:pastebin.com+{query}" },
];
