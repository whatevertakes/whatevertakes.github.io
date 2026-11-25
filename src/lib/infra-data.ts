import { getCollection } from 'astro:content';

// src/content/infra/ 의 YAML을 읽어 참조 무결성을 검사하고, 지도 화면이 쓰는 형태로 바꾼다.
// 검사에 실패하면 빌드를 멈춘다 (PR 검사와 배포 모두에서).

export async function loadInfraData() {
  const [areas, links, oss, vulns, incidents, companies, usage] = await Promise.all([
    getCollection('areas'), getCollection('links'), getCollection('oss'), getCollection('vulns'),
    getCollection('incidents'), getCollection('companies'), getCollection('usage'),
  ]);

  const problems: string[] = [];
  const has = (list: { id: string }[]) => new Set(list.map((e) => e.id));
  const areaIds = has(areas), linkIds = has(links), ossIds = has(oss), vulnIds = has(vulns), companyIds = has(companies);
  const need = (set: Set<string>, id: string, where: string) => { if (!set.has(id)) problems.push(`${where}: 없는 ID "${id}"`); };

  for (const id of Array.from({ length: 16 }, (_, i) => String(i + 1))) need(areaIds, id, 'areas.yaml');
  for (const a of areas) {
    a.data.oss.forEach((o) => need(ossIds, o, `areas.yaml 영역 ${a.id}의 oss`));
    a.data.links.forEach((l) => need(linkIds, l, `areas.yaml 영역 ${a.id}의 links`));
  }
  for (const o of oss) o.data.areas.forEach((x) => need(areaIds, x, `oss/${o.id}`));
  for (const v of vulns) {
    v.data.areas.forEach((x) => need(areaIds, x, `vulns/${v.id}`));
    if (v.data.list === 'recent' && !v.data.kev) problems.push(`vulns/${v.id}: list가 recent이면 kev 정보가 필요`);
  }
  for (const i of incidents) {
    i.data.areas.forEach((x) => need(areaIds, x, `incidents/${i.id}`));
    Object.keys(i.data.notes ?? {}).forEach((x) => { if (!i.data.areas.includes(x)) problems.push(`incidents/${i.id}: notes의 영역 ${x}가 areas에 없음`); });
    (i.data.vulns ?? []).forEach((x) => need(vulnIds, x, `incidents/${i.id}의 vulns`));
  }
  for (const c of companies) {
    c.data.services.forEach((s) => s.areas.forEach((x) => need(areaIds, x, `companies/${c.id} 서비스 "${s.name}"`)));
    c.data.incidents.forEach((s) => s.areas.forEach((x) => need(areaIds, x, `companies/${c.id} 사건`)));
  }
  for (const u of usage) {
    need(companyIds, u.data.company, `usage/${u.id}`);
    need(ossIds, u.data.oss, `usage/${u.id}`);
    if (u.id !== `${u.data.company}__${u.data.oss}`) problems.push(`usage/${u.id}: 파일 이름은 <company>__<oss>.yaml 이어야 함`);
  }
  if (problems.length) throw new Error('인프라 지도 데이터 검사 실패\n- ' + problems.join('\n- '));

  // 지도 화면 형태로 변환
  const num = (s: string) => Number(s);
  const byDateDesc = (a: string, b: string) => b.localeCompare(a);
  const ossName = new Map(oss.map((o) => [o.id, o.data.name]));
  const A = areas
    .sort((a, b) => num(a.id) - num(b.id))
    .map((a) => ({
      id: num(a.id), name: a.data.name, en: a.data.en, b: a.data.bounty, sum: a.data.summary, kr: a.data.korea,
      oss: a.data.oss.map((o) => ossName.get(o)!),
      cves: vulns.filter((v) => v.data.list === 'base' && v.data.areas.includes(a.id)).sort((x, y) => byDateDesc(x.id, y.id)).map((v) => [v.id, v.data.summary]),
      inc: incidents.filter((i) => !i.data.recent && i.data.areas.includes(a.id)).sort((x, y) => byDateDesc(x.data.date, y.data.date)).map((i) => [i.data.title, i.data.notes?.[a.id] ?? i.data.summary]),
      q: [a.data.questions.operator, a.data.questions.attacker, a.data.questions.defender],
      db: a.data.links,
    }));
  const N26: Record<number, unknown[]> = {}, I26: Record<number, unknown[]> = {};
  for (const a of areas) {
    N26[num(a.id)] = vulns.filter((v) => v.data.list === 'recent' && v.data.areas.includes(a.id))
      .sort((x, y) => byDateDesc(x.data.kev!.date, y.data.kev!.date))
      .map((v) => [v.id, v.data.kev!.date, v.data.summary, v.data.kev!.ransomware ? 1 : 0]);
    const rec = incidents.filter((i) => i.data.recent && i.data.areas.includes(a.id));
    if (rec.length) I26[num(a.id)] = rec.map((i) => [i.data.title, i.data.notes?.[a.id] ?? i.data.summary, i.data.sources[0] ?? null]);
  }
  const SEV = Object.fromEntries(vulns.filter((v) => v.data.cvss).map((v) => [v.id, [v.data.cvss!.score, v.data.cvss!.version]]));
  const DB = Object.fromEntries(links.map((l) => [l.id, [l.data.title, l.data.url]]));
  const sorted = companies.sort((a, b) => a.data.order - b.data.order);
  const CO = sorted.map((c) => ({
    id: c.id, name: c.data.name, kr: c.data.region === 'kr' ? 1 : 0, tag: c.data.tag,
    svc: c.data.services.map((s) => [s.name, s.areas.map(num)]),
    infra: c.data.infra,
    inc: c.data.incidents.map((i) => [i.date, i.text, i.areas.map(num), i.source ?? null]),
    bb: [{ yes: 'y', no: 'n', unknown: '?' }[c.data.bounty.status], c.data.bounty.note, c.data.bounty.url ?? null],
    tip: c.data.tip, blog: c.data.blog ?? null,
  }));
  const DEEP = Object.fromEntries(sorted.filter((c) => c.data.deep).map((c) => {
    const d = c.data.deep!;
    return [c.id, {
      sub: d.summary,
      facts: d.facts.map((f) => [f.label, f.value, f.detail]),
      svc: d.services.map((s) => [s.name, Object.fromEntries(Object.entries(s.areas).map(([k, v]) => [k, v === 'core' ? 2 : 1]))]),
      cards: Object.fromEntries(Object.entries(d.areas).map(([k, v]) => [k, [v.here, v.risk, v.study, v.sources.map((s) => [s.title, s.url]), v.level ?? null]])),
      paths: (d.paths ?? []).map((p) => [p.title, p.steps.map((st) => [st.area, st.label]), p.source ?? null]),
      tl: d.timeline.map((t) => [t.date, t.text, t.bad ? 1 : 0]),
      use: d.use.map((u) => [u.title, u.style, u.items, u.note]),
    }];
  }));
  const counts = { areas: areas.length, oss: oss.length, vulns: vulns.length, incidents: incidents.length, companies: companies.length, usage: usage.length };
  return { A, N26, I26, SEV, DB, CO, DEEP, counts };
}
