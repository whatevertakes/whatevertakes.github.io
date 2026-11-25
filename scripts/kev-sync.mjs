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

const newest = kev.vulnerabilities.reduce((m, v) => (v.dateAdded > m ? v.dateAdded : m), state.last_date);
if (newest !== state.last_date) {
  state.last_date = newest;
  await writeFile(STATE, JSON.stringify(state, null, 2) + '\n');
}

const row = (x) => `| ${x.v.dateAdded} | [${x.v.cveID}](https://nvd.nist.gov/vuln/detail/${x.v.cveID}) | ${x.v.vendorProject} ${x.v.product} | ${x.area} ${AREA_NAMES[x.area]} | ${x.score ? x.score.score : '없음'} | ${x.v.knownRansomwareCampaignUse === 'Known' ? '예' : ''} |`;
const body = [
  `CISA KEV에 ${state.last_date}까지 새로 등재된 항목을 반영합니다. 실제 악용이 확인된 취약점입니다.`,
  '',
  `## 추가 (${added.length}건)`,
  '',
  added.length ? '| KEV 등재일 | CVE | 제품 | 자동 분류 영역 | CVSS | 랜섬웨어 |\n|---|---|---|---|---|---|\n' + added.map(row).join('\n') : '없음',
  '',
  `## 영역 분류 필요 (${unmapped.length}건)`,
  '',
  unmapped.length ? '자동 분류 규칙에 맞지 않아 파일을 만들지 않았습니다. 필요하면 직접 추가하거나 `scripts/kev-area-rules.json`에 규칙을 더해 주세요.\n\n' + unmapped.map((v) => `- ${v.dateAdded} [${v.cveID}](https://nvd.nist.gov/vuln/detail/${v.cveID}) ${v.vendorProject} ${v.product}: ${v.vulnerabilityName}`).join('\n') : '없음',
  '',
  '## 검토할 것',
  '',
  '- 자동 분류된 영역이 맞는지 확인합니다.',
  '- `summary`는 KEV 영어 원문입니다. 한국어 한 줄 요약으로 바꿔 주세요.',
  '- 이 PR은 워크플로 안에서 사이트 빌드(스키마·참조 검사)를 통과한 뒤 열렸습니다.',
  '',
  '출처: [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (미러: github.com/cisagov/kev-data), CVSS: github.com/CVEProject/cvelistV5',
].join('\n');
await writeFile(PR_BODY, body + '\n');

if (process.env.GITHUB_OUTPUT) await writeFile(process.env.GITHUB_OUTPUT, `added=${added.length}\nunmapped=${unmapped.length}\nlast_date=${state.last_date}\n`, { flag: 'a' });
console.log(`KEV 동기화: 추가 ${added.length}, 분류 필요 ${unmapped.length}, 기준일 ${state.last_date}`);
