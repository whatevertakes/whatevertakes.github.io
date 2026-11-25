// CISA KEV 자동 동기화.
// 마지막 동기화 이후 KEV에 새로 등재된 항목을 src/content/infra/vulns/ 에 YAML로 추가하고,
// PR 설명(마크다운)을 만든다. 외부 패키지 없이 Node 22로 실행한다.
//
//   node scripts/kev-sync.mjs
//
// 환경 변수
//   KEV_FILE   KEV JSON 로컬 경로(테스트용). 없으면 KEV_URL에서 받는다.
//   KEV_URL    기본값: cisagov/kev-data 미러의 known_exploited_vulnerabilities.json
//   PR_BODY    PR 설명을 쓸 경로. 기본값: <임시 폴더>/kev-sync-pr.md
//   GITHUB_OUTPUT  GitHub Actions에서 added, unmapped 개수를 넘길 때 사용

import { readFile, writeFile, readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = new URL('..', import.meta.url).pathname;
const VULNS = join(ROOT, 'src/content/infra/vulns');
const STATE = join(ROOT, 'scripts/kev-sync-state.json');
const RULES = join(ROOT, 'scripts/kev-area-rules.json');
const KEV_URL = process.env.KEV_URL ?? 'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json';
const PR_BODY = process.env.PR_BODY ?? join(tmpdir(), 'kev-sync-pr.md');
const AREA_NAMES = { 1: '물리', 2: '네트워크', 3: '컴퓨팅·OS', 4: '가상화·컨테이너', 5: '스토리지·백업', 6: '데이터·미들웨어', 7: '아이덴티티', 8: '사내 IT', 9: '클라우드', 10: '자동화·배포', 11: '운영·관측', 12: '보안', 13: '특수 인프라', 14: '애플리케이션', 15: '공급망', 16: 'AI 인프라' };

const json = async (url) => {
  const res = await fetch(url, { headers: { 'user-agent': 'wt-infra-map-kev-sync' } });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
};

// CVE 공식 레코드에서 CVSS 기본 점수를 고른다. 3.1 > 3.0 > 4.0 순.
async function cvss(cve) {
  const [, y, n] = cve.split('-');
  const url = `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/${y}/${n.slice(0, -3)}xxx/${cve}.json`;
  try {
    const rec = await json(url);
    const found = [];
    const walk = (o) => {
      if (Array.isArray(o)) return o.forEach(walk);
      if (o && typeof o === 'object') for (const [k, v] of Object.entries(o)) {
        if (/^cvssV\d_\d$/.test(k) && v && typeof v.baseScore === 'number') found.push([k, v.baseScore]);
        else walk(v);
      }
    };
    walk(rec.containers ?? {});
    const order = { cvssV3_1: 0, cvssV3_0: 1, cvssV4_0: 2, cvssV2_0: 3 };
    found.sort((a, b) => (order[a[0]] ?? 9) - (order[b[0]] ?? 9));
    if (!found.length) return null;
    return { score: found[0][1], version: found[0][0].replace('cvssV', '').replace('_', '.') };
  } catch {
    return null; // 레코드가 아직 없으면 점수 없이 추가
  }
}

const q = (s) => JSON.stringify(String(s)); // YAML에서도 유효한 큰따옴표 문자열

function toYaml(v, area, score) {
  const lines = [
    `# 자동 추가: KEV 동기화 (${v.dateAdded}). summary는 KEV 원문이므로 한국어 요약으로 바꿔 주세요.`,
    `summary: ${q(v.vulnerabilityName)}`,
    `areas: [${q(area)}]`,
    `list: recent`,
    `kev: { date: ${q(v.dateAdded)}, ransomware: ${v.knownRansomwareCampaignUse === 'Known'} }`,
  ];
  if (score) lines.push(`cvss: { score: ${score.score}, version: ${q(score.version)}, source: "CVE 레코드(cvelistV5)" }`);
  return lines.join('\n') + '\n';
}

const state = JSON.parse(await readFile(STATE, 'utf8'));
const rules = JSON.parse(await readFile(RULES, 'utf8')).rules.map((r) => ({ area: r.area, re: new RegExp(r.match, 'i') }));
const kev = process.env.KEV_FILE ? JSON.parse(await readFile(process.env.KEV_FILE, 'utf8')) : await json(KEV_URL);
const existing = new Set((await readdir(VULNS)).map((f) => f.replace(/\.ya?ml$/, '')));

const fresh = kev.vulnerabilities
  .filter((v) => v.dateAdded > state.last_date && !existing.has(v.cveID))
  .sort((a, b) => a.dateAdded.localeCompare(b.dateAdded) || a.cveID.localeCompare(b.cveID));

const added = [], unmapped = [];
for (const v of fresh) {
  const text = `${v.vendorProject} ${v.product} ${v.vulnerabilityName}`.toLowerCase();
  const rule = rules.find((r) => r.re.test(text));
  if (!rule) { unmapped.push(v); continue; }
  const score = await cvss(v.cveID);
  const file = join(VULNS, `${v.cveID}.yaml`);
  if (!existsSync(file)) await writeFile(file, toYaml(v, rule.area, score));
  added.push({ v, area: rule.area, score });
}

// 이미 있는 항목 갱신: KEV가 나중에 바꾸는 랜섬웨어 사용 표시, 늦게 발행된 CVE 레코드의 CVSS 점수
const kevById = new Map(kev.vulnerabilities.map((v) => [v.cveID, v]));
const updated = [];
for (const name of (await readdir(VULNS)).filter((f) => f.endsWith('.yaml'))) {
  const id = name.replace(/\.yaml$/, '');
  if (added.some((x) => x.v.cveID === id)) continue;
  const file = join(VULNS, name);
  let text = await readFile(file, 'utf8');
  const before = text, notes = [];
  const k = kevById.get(id);
  if (k?.knownRansomwareCampaignUse === 'Known' && /ransomware:\s*false/.test(text)) {
    text = text.replace(/ransomware:\s*false/, 'ransomware: true');
    notes.push('랜섬웨어 사용 확인으로 변경');
  }
  if (!/^cvss:/m.test(text)) {
    const score = await cvss(id);
    if (score) {
      text = text.replace(/\n*$/, '\n') + `cvss: { score: ${score.score}, version: ${q(score.version)}, source: "CVE 레코드(cvelistV5)" }\n`;
      notes.push(`CVSS ${score.score} 추가`);
    }
  }
  if (text !== before) { await writeFile(file, text); updated.push({ id, notes }); }
}

const newest = kev.vulnerabilities.reduce((m, v) => (v.dateAdded > m ? v.dateAdded : m), state.last_date);
if (newest !== state.last_date) {
  state.last_date = newest;
  await writeFile(STATE, JSON.stringify(state, null, 2) + '\n');
}

// PR 설명: 맨 위에 사람이 할 일 체크리스트, 항목마다 바로 고치는 링크
const REPO = process.env.GITHUB_REPOSITORY ?? 'whatevertakes/whatevertakes.github.io';
const BRANCH = process.env.SYNC_BRANCH ?? 'kev-sync/auto';
const editUrl = (id) => `https://github.com/${REPO}/edit/${BRANCH}/src/content/infra/vulns/${id}.yaml`;
const newUrl = (v) => `https://github.com/${REPO}/new/${BRANCH}/src/content/infra/vulns?filename=${v.cveID}.yaml&value=${encodeURIComponent(toYaml(v, '?', null))}`;
const nvd = (id) => `[${id}](https://nvd.nist.gov/vuln/detail/${id})`;
const row = (x) => `| ${x.v.dateAdded} | ${nvd(x.v.cveID)} | ${x.v.vendorProject} ${x.v.product} | **${x.area}** ${AREA_NAMES[x.area]} | ${x.score ? x.score.score : '없음'} | ${x.v.knownRansomwareCampaignUse === 'Known' ? '예' : ''} | ${x.v.vulnerabilityName} | [고치기](${editUrl(x.v.cveID)}) |`;
const minutes = Math.max(2, added.length + unmapped.length * 2);
const todo = [
  `## 사람이 할 일 (약 ${minutes}분)`,
  '',
  '> 이 PR의 브랜치는 다음 날 동기화 때 새로 덮어써집니다. **고친 내용은 그날 바로 병합**해 주세요.',
  '',
];
if (added.length) todo.push(
  `- [ ] **1. 영역 확인** — 아래 「추가」 표의 **자동 분류 영역**이 제품과 맞는지 봅니다. 틀리면 그 줄의 **고치기**를 눌러 \`areas: ["6"]\`의 숫자를 바꾸고 *Commit changes*를 누릅니다. (번호표는 맨 아래)`,
  `- [ ] **2. 한국어 요약** — 각 줄의 **고치기**에서 \`summary:\`의 영어 원문을 한국어 한 줄로 바꿉니다. 이 문장이 지도 화면에 그대로 보입니다.`,
  '  - 예: `"Apache ActiveMQ Improper Input Validation Vulnerability"` → `"Apache ActiveMQ 입력 검증 결함으로 코드 실행"`',
  '  - 무엇이 문제이고(코드 실행, 인증 우회, 경로 조작 등) 어떤 제품인지만 짧게. 공격 방법은 쓰지 않습니다.',
);
if (unmapped.length) todo.push(
  `- [ ] **3. 분류 필요 ${unmapped.length}건** — 지도에 넣을 항목만 처리합니다. 「영역 분류 필요」의 **새 파일 만들기**를 누르면 내용이 채워진 파일이 열립니다. \`areas: ["?"]\`의 \`?\`를 영역 번호로 바꾸고, 요약을 한국어로 바꾼 뒤 *Commit changes*. 넣지 않을 항목은 건너뜁니다.`,
  '  - 자주 나오는 제품이면 `scripts/kev-area-rules.json`에 규칙을 더하면 다음부터 자동 분류됩니다.',
);
todo.push(
  `- [ ] **${unmapped.length ? 4 : added.length ? 3 : 1}. 병합** — 고친 뒤 빌드 검사(✅)가 통과하면 *Merge*를 누릅니다. 병합하면 사이트 지도에 자동 반영됩니다(영역 타일 숫자, 최근 실제 악용 상자, 색인, 위험도 필터).`,
  '',
  '이 PR은 만들어지기 전에 사이트 빌드(스키마·참조 검사)를 통과했습니다. 고친 뒤 빌드가 실패하면 PR 아래 검사 로그에 문제 파일이 나옵니다.',
  '',
);
const body = [
  ...todo,
  `## 추가 (${added.length}건)`,
  '',
  added.length ? '| KEV 등재일 | CVE | 제품 | 자동 분류 영역 | CVSS | 랜섬웨어 | KEV 원문(요약 참고) | |\n|---|---|---|---|---|---|---|---|\n' + added.map(row).join('\n') : '없음',
  '',
  `## 영역 분류 필요 (${unmapped.length}건)`,
  '',
  unmapped.length ? unmapped.map((v) => `- ${v.dateAdded} ${nvd(v.cveID)} ${v.vendorProject} ${v.product}: ${v.vulnerabilityName} — [새 파일 만들기](${newUrl(v)})`).join('\n') : '없음',
  '',
  `## 기존 항목 자동 갱신 (${updated.length}건, 확인만)`,
  '',
  updated.length ? updated.map((u) => `- ${nvd(u.id)}: ${u.notes.join(', ')}`).join('\n') : '없음',
  '',
  '<details><summary>영역 번호표</summary>',
  '',
  Object.entries(AREA_NAMES).map(([k, v]) => `${k} ${v}`).join(' · '),
  '',
  '</details>',
  '',
  '출처: [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (미러: github.com/cisagov/kev-data), CVSS: github.com/CVEProject/cvelistV5',
].join('\n');
// GitHub PR 본문 한도(65,536자)를 넘지 않게 자른다. 파일과 링크는 PR의 Files changed에 그대로 있다.
const LIMIT = 60000;
const finalBody = body.length > LIMIT ? body.slice(0, LIMIT) + '\n\n…(본문이 길어 잘렸습니다. 나머지는 Files changed 탭에서 확인하세요.)' : body;
await writeFile(PR_BODY, finalBody + '\n');

if (process.env.GITHUB_OUTPUT) await writeFile(process.env.GITHUB_OUTPUT, `added=${added.length}\nupdated=${updated.length}\nchanged=${added.length + updated.length}\nunmapped=${unmapped.length}\nlast_date=${state.last_date}\n`, { flag: 'a' });
console.log(`KEV 동기화: 추가 ${added.length}, 갱신 ${updated.length}, 분류 필요 ${unmapped.length}, 기준일 ${state.last_date}`);
