// SmartAudit Web - deterministic, read-only preliminary checks.
// Findings are review candidates, never proof of an exploitable vulnerability.
export const RULESET_VERSION = "1.0.0";
const ADDRESS = /^0x[a-fA-F0-9]{40}$/;
const CHAINS = { "etherscan.io": 1, "sepolia.etherscan.io": 11155111, "hoodi.etherscan.io": 560048, "holesky.etherscan.io": 17000 };

export function parseEtherscanUrl(value) {
  let u;
  try { u = new URL(String(value).trim()); } catch { throw new Error("URL không hợp lệ. Hãy dán liên kết trang hợp đồng từ Etherscan."); }
  const host = u.hostname.toLowerCase();
  if (u.protocol !== "https:" || u.port || u.username || u.password || !(host in CHAINS)) {
    throw new Error("Chỉ chấp nhận URL HTTPS thuộc etherscan.io hoặc mạng thử nghiệm Etherscan hỗ trợ.");
  }
  const hit = /^\/(?:address|token)\/(0x[a-fA-F0-9]{40})\/?$/i.exec(u.pathname);
  if (!hit) throw new Error("URL phải có dạng https://etherscan.io/address/0x... (40 ký tự hex).");
  return { address: hit[1], chainId: CHAINS[host], host, url: u.origin + "/address/" + hit[1] + "#code" };
}
export function validAddress(address) { return ADDRESS.test(String(address)); }

export function normalizeEtherscan(item, chainId, address) {
  if (!item || typeof item.SourceCode !== "string" || !item.SourceCode.trim()) throw new Error("Etherscan chưa cung cấp mã nguồn xác thực cho địa chỉ này.");
  const raw = item.SourceCode.trim();
  let files = {};
  if (raw.startsWith("{")) {
    try {
      const obj = JSON.parse(raw.startsWith("{{") ? raw.slice(1, -1) : raw);
      if (obj.language && obj.language.toLowerCase() !== "solidity") throw new Error("Hợp đồng không viết bằng Solidity.");
      if (obj.sources && typeof obj.sources === "object") for (const [name, entry] of Object.entries(obj.sources)) {
        if (typeof entry?.content === "string") files[name] = entry.content;
      }
    } catch (error) { if (error.message.includes("không viết bằng Solidity")) throw error; }
  }
  if (!Object.keys(files).length) files[item.ContractFileName || item.ContractName + ".sol" || "Contract.sol"] = raw;
  return {
    address, chainId, name: item.ContractName || "Contract",
    compilerVersion: item.CompilerVersion || "Không rõ",
    sourceProvider: "Etherscan API v2",
    verification: "Etherscan verified",
    isProxy: item.Proxy === "1", implementation: validAddress(item.Implementation) ? item.Implementation : null,
    files
  };
}
export function normalizeSourcify(item, chainId, address) {
  if (!item || !item.sources || typeof item.sources !== "object") throw new Error("Chưa tìm thấy mã nguồn trên Sourcify.");
  if (String(item.compilation?.language || "Solidity").toLowerCase() !== "solidity") throw new Error("Hợp đồng không viết bằng Solidity.");
  const files = {};
  for (const [name, entry] of Object.entries(item.sources)) if (typeof entry?.content === "string") files[name] = entry.content;
  if (!Object.keys(files).length) throw new Error("Sourcify chưa trả về tệp mã nguồn.");
  const impl = item.proxyResolution?.implementations?.find(x => validAddress(x.address))?.address || null;
  return {
    address, chainId, name: item.compilation?.name || "Contract",
    compilerVersion: item.compilation?.compilerVersion || "Không rõ",
    sourceProvider: "Sourcify API v2", verification: item.match || "verified",
    isProxy: Boolean(item.proxyResolution?.isProxy), implementation: impl, files
  };
}
// Maintain character offsets and newlines while removing comments and literals.
export function withoutCommentsAndStrings(source) {
  const text = String(source); let out = "", mode = "code", quote = "";
  for (let i = 0; i < text.length; i++) {
    const ch = text[i], next = text[i + 1];
    if (mode === "code") {
      if (ch === "/" && next === "/") { out += "  "; i++; mode = "line"; continue; }
      if (ch === "/" && next === "*") { out += "  "; i++; mode = "block"; continue; }
      if (ch === '"' || ch === "'") { quote = ch; out += " "; mode = "string"; continue; }
      out += ch; continue;
    }
    if (mode === "line") { if (ch === "\n") { out += "\n"; mode = "code"; } else out += " "; continue; }
    if (mode === "block") {
      if (ch === "*" && next === "/") { out += "  "; i++; mode = "code"; }
      else out += ch === "\n" ? "\n" : " ";
      continue;
    }
    if (mode === "string") {
      if (ch === "\\" && i + 1 < text.length) { out += "  "; i++; }
      else if (ch === quote) { out += " "; mode = "code"; }
      else out += ch === "\n" ? "\n" : " ";
    }
  }
  return out;
}
const RULES = [
  { id: "SA-001", severity: "high", title: "Phụ thuộc tx.origin", re: /\btx\s*\.\s*origin\b/g, detail: "Nếu tx.origin được dùng để phân quyền, giao dịch qua hợp đồng trung gian có thể tạo rủi ro. Kiểm tra đường gọi và quyền thực tế.", fix: "Đối chiếu với mô hình phân quyền thích hợp, thường là msg.sender và role/access control." },
  { id: "SA-002", severity: "medium", title: "Delegatecall cần xem xét", re: /\bdelegatecall\s*\(/g, detail: "delegatecall chạy mã đích trong ngữ cảnh storage của hợp đồng gọi. Đây là cơ chế hợp lệ cho proxy nhưng phải kiểm toán mục tiêu và quyền cập nhật.", fix: "Kiểm tra nguồn địa chỉ đích, storage layout, quyền nâng cấp và trình khởi tạo." },
  { id: "SA-003", severity: "medium", title: "Gọi ngoài kèm chuyển ETH", re: /\.\s*call\s*\{\s*value\s*:/g, detail: "Lời gọi ngoài có chuyển ETH. Cần kiểm tra reentrancy và trình tự cập nhật trạng thái, không kết luận tự động có thể tấn công.", fix: "Rà soát Checks-Effects-Interactions, reentrancy guard và xử lý giá trị trả về." },
  { id: "SA-004", severity: "medium", title: "Thao tác selfdestruct", re: /\bselfdestruct\s*\(/g, detail: "Ngữ nghĩa SELFDESTRUCT phụ thuộc hard fork và thời điểm tạo hợp đồng; cần kiểm tra tác động thực tế theo chain.", fix: "Xác định EVM fork, quyền gọi và cân nhắc bỏ chức năng nếu không cần." },
  { id: "SA-005", severity: "low", title: "Dùng thời gian khối", re: /\bblock\s*\.\s*timestamp\b/g, detail: "Timestamp không phải nguồn ngẫu nhiên an toàn; chỉ nguy hiểm tùy cách dùng trong logic.", fix: "Không dùng timestamp để sinh ngẫu nhiên; đánh giá biên thời gian cho nghiệp vụ." },
  { id: "SA-006", severity: "low", title: "Dùng blockhash", re: /\bblockhash\s*\(/g, detail: "Blockhash không phải nguồn ngẫu nhiên chống thao túng; cần xem logic tiêu thụ.", fix: "Dùng nguồn ngẫu nhiên có thể kiểm chứng khi nghiệp vụ đòi hỏi." },
  { id: "SA-007", severity: "medium", title: "Phép toán unchecked", re: /\bunchecked\s*\{/g, detail: "Solidity 0.8+ bỏ kiểm tra overflow/underflow trong khối unchecked; không sai nếu có bất biến đảm bảo.", fix: "Chứng minh miền giá trị và kiểm thử biên số học." },
  { id: "SA-008", severity: "low", title: "Có inline assembly", re: /\bassembly\s*(?:\([^)]*\)\s*)?\{/g, detail: "Assembly bỏ qua một số cơ chế bảo vệ của ngôn ngữ mức cao.", fix: "Rà soát bộ nhớ, storage, return data và giả định EVM." },
  { id: "SA-009", severity: "low", title: "Có ecrecover", re: /\becrecover\s*\(/g, detail: "Xác thực chữ ký cần kiểm tra domain separation, nonce, replay và kiểm tra signer.", fix: "Ưu tiên thư viện ECDSA chuẩn và EIP-712 khi phù hợp." },
  { id: "SA-010", severity: "low", title: "Dùng abi.encodePacked", re: /\babi\s*\.\s*encodePacked\s*\(/g, detail: "Chỉ gây va chạm mã hóa kiểu động khi các thành phần không phân định ranh giới và đầu ra dùng làm mã băm bảo mật.", fix: "Kiểm tra tham số; cân nhắc abi.encode khi cần mã hóa không mơ hồ." },
  { id: "SA-011", severity: "low", title: "Có phép gọi .send", re: /\.\s*send\s*\(/g, detail: "send trả về bool, nếu không kiểm tra có thể bỏ qua lỗi chuyển ETH.", fix: "Kiểm tra bool trả về và cân nhắc phương án chuyển ETH an toàn." },
  { id: "SA-012", severity: "low", title: "Có phép gọi .transfer", re: /\.\s*transfer\s*\(/g, detail: "transfer dựa vào giới hạn gas cố định; đối với một số địa chỉ/hard fork có thể thất bại.", fix: "Xác minh kiểu đối tượng (ETH hay token), xem xét cơ chế call có kiểm soát." }
];
const order = { high: 0, medium: 1, low: 2, info: 3 };
export function analyzeContract(contract) {
  const files = Object.entries(contract.files || {}).filter(([,v]) => typeof v === "string");
  if (!files.length) throw new Error("Không có nguồn Solidity hợp lệ để phân tích.");
  let totalBytes = 0; const findings = [];
  const versionMatch = /v?(\d+)\.(\d+)\.(\d+)/.exec(contract.compilerVersion || "");
  const version = versionMatch ? versionMatch.slice(1, 4).map(Number) : null;
  for (const [file, source] of files) {
    totalBytes += source.length;
    if (totalBytes > 2_000_000 || files.length > 250) throw new Error("Mã nguồn vượt giới hạn 2 MB hoặc 250 tệp cho chế độ rà soát nhanh.");
    const clean = withoutCommentsAndStrings(source);
    const lineStarts = [0];
    for (let i = 0; i < clean.length; i++) if (clean[i] === "\n") lineStarts.push(i + 1);
    const getLine = index => {
      let lo = 0, hi = lineStarts.length - 1;
      while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (lineStarts[mid] <= index) lo = mid; else hi = mid - 1; }
      return lo + 1;
    };
    const originals = source.split(/\r?\n/);
    for (const rule of RULES) {
      if (rule.id === "SA-007" && version && (version[0] === 0 && version[1] < 8)) continue;
      const re = new RegExp(rule.re.source, rule.re.flags); let hit, count = 0, lastLine = 0;
      while ((hit = re.exec(clean)) && count < 20) {
        const line = getLine(hit.index);
        if (line === lastLine) continue;
        lastLine = line; count++;
        findings.push({ id: rule.id, severity: rule.severity, title: rule.title, file, line, snippet: (originals[line - 1] || "").trim().slice(0, 240), detail: rule.detail, fix: rule.fix, confidence: "Cần kiểm chứng", source: "heuristic" });
      }
    }
  }
  if (version && version[0] === 0 && version[1] < 8) findings.push({
    id: "SA-013", severity: "medium", title: "Solidity trước 0.8: số học không tự kiểm tra tràn",
    file: "metadata", line: null, snippet: contract.compilerVersion,
    detail: "Phiên bản compiler trước 0.8 không mặc định revert với overflow/underflow. Chưa chứng minh có đường khai thác.",
    fix: "Đối chiếu SafeMath, bất biến số học, phép toán thực tế và ràng buộc đầu vào.", confidence: "Cần kiểm chứng", source: "version"
  });
  if (!version) findings.push({
    id: "SA-014", severity: "info", title: "Không xác định được compiler thực tế",
    file: "metadata", line: null, snippet: contract.compilerVersion || "Không rõ",
    detail: "Phạm vi các kiểm tra theo phiên bản bị hạn chế.", fix: "Lấy compilerVersion chính xác từ metadata xác thực.", confidence: "Thông tin", source: "metadata"
  });
  if (contract.isProxy) findings.push({
    id: "SA-015", severity: "medium", title: "Proxy: cần kiểm toán cả implementation",
    file: "metadata", line: null, snippet: contract.implementation || "Chưa xác định địa chỉ implementation",
    detail: "Mã nguồn proxy không đại diện cho toàn bộ logic runtime. Chưa tự động khẳng định implementation an toàn.",
    fix: "Phân tích implementation, initializer, quyền upgrade và tương thích storage.", confidence: "Cần kiểm chứng", source: "metadata"
  });
  findings.sort((a,b) => order[a.severity] - order[b.severity] || a.file.localeCompare(b.file) || (a.line||0) - (b.line||0));
  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return { contract: { address: contract.address, chainId: contract.chainId, name: contract.name, compilerVersion: contract.compilerVersion, sourceProvider: contract.sourceProvider, verification: contract.verification, isProxy: contract.isProxy, implementation: contract.implementation }, files: files.length, bytes: totalBytes, rulesetVersion: RULESET_VERSION, mode: "Heuristic / rà soát sơ bộ, không phải kiểm toán toàn diện", findings, counts, generatedAt: new Date().toISOString() };
}
